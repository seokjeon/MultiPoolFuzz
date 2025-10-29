import random
from itertools import groupby
from fuzzingbook.Fuzzer import Runner
from fuzzingbook.Coverage import Location, Coverage
from fuzzingbook.MutationFuzzer import FunctionRunner
from fuzzingbook.GreyboxFuzzer import AdvancedMutationFuzzer, PowerSchedule, getPathID
from typing import Iterator, Set, List, Dict, Any, Tuple, Union

class Seed:
    def __init__(self, data: str) -> None:
        """Initialize from seed data"""
        self.data = data
        self.coverage: Set[Location] = set()
        self.distance: Union[int, float] = -1
        self.trace: List[Location] = []
        self.energy = 0.0
        self.population_id = 0  # 시드가 속한 풀 ID

    def __str__(self) -> str:
        return self.data
    __repr__ = __str__

class Population:
    def __init__(self, id, initial_seeds):
        self.id = id
        self.initial_seeds = initial_seeds
        self.energy = 0.0
        self.data = self.initial_seeds

    def __getitem__(self, index: int) -> Seed:
        return self.data[index]

    def __setitem__(self, index: int, value: Seed) -> None:
        self.data[index] = value
    
    def append(self, value: Seed) -> None:
        self.data.append(value)

    def __len__(self) -> int:
        return len(self.data)

    def __iter__(self) -> Iterator[Seed]:
        return iter(self.data)
        
    def __str__(self) -> str:
        return str(self.data)
    __repr__ = __str__

class MultiPoolFunctionTraceRunner(FunctionRunner):

    def __init__(self, running_process, target_program):
        super().__init__(running_process)
        self._trace = list()
        self.filter = DynamicFunctionFilter(['b1', 'a2', 'd3', 'ex', 'leaf_crash'], target_program)

    def run_function(self, inp: str) -> Any:
        try:
            with Coverage() as cov:
                result = super().run_function(inp)
        except Exception as exc:
            raise exc
        finally:
            # 정상/예외 관계없이 항상 coverage 수집
            self._coverage = set(self.filter.debug_symbols(cov.coverage()))
            
            # trace 처리 - 중복 제거 및 필터링을 한 번에
            raw_trace = cov.trace()
            unique_functions = [func_name for func_name, _ in groupby(raw_trace, key=lambda x: x[0])]
            self._trace = [f for f in unique_functions if f in self.filter.allowed_functions]
        
        return result

    def coverage(self) -> Set[Location]:
        return self._coverage
    
    def trace(self):
        return self._trace
    
class DynamicFunctionFilter:
    def __init__(self, vuln_callstack, target_program=None):
        self.vuln_callstack = vuln_callstack
        self.allowed_functions = self._build_allowed_functions(target_program)
    
    def _build_allowed_functions(self, target_program):
        allowed = set(self.vuln_callstack)
        
        if target_program:
            import inspect
            for name, obj in inspect.getmembers(target_program):
                if (inspect.isfunction(obj) and 
                    not name.startswith('_') and
                    not name.startswith('__')):
                    allowed.add(name)
        
        return allowed
    
    def debug_symbols(self, trace):
        return [item for item in trace if item[0] in self.allowed_functions]

class MultiPoolSchedule(PowerSchedule):
    """멀티풀 스케줄러 - 명세 2.1~2.2 구현"""
    
    def __init__(self, vuln_callstack, exponent, prob=0.8) -> None:
        super().__init__()
        self.vuln_callstack = vuln_callstack
        self.exponent = exponent
        self.population_frequency = {idx: 0 for idx in range(len(self.vuln_callstack)+1, -1, -1)}
        self.current_population_idx = 0
        self.prob = prob

    def assignPopulationEnergy(self, populations):
        """population에 에너지 할당"""
        for population_id, population in populations.items():
            if population_id in self.population_frequency:
                try: 
                    population.energy = 1 / (self.population_frequency[population_id] ** self.exponent)
                except ZeroDivisionError:
                    population.energy = 1.0
            else:
                population.energy = 1.0

    def assignSeedEnergy(self, population):
        """population에 에너지 할당"""
        for seed in population:
            seed.energy = 1 / (self.path_frequency[getPathID(seed.coverage)] ** self.exponent)


    def normalizedEnergy(self, collection) -> List[float]:
        """Normalize energy"""
        energy = list(map(lambda elem: elem.energy, collection))
        sum_energy = sum(energy)  # Add up all values in energy
        assert sum_energy != 0
        norm_energy = list(map(lambda nrg: nrg / sum_energy, energy))
        return norm_energy
        
    def choose_population(self, seed_pool):
        """명세 2.1: 개체군 선택 (평균 선택 빈도의 역수를 에너지로)"""
            
        # # 각 개체군의 평균 선택 빈도 계산
        # self.assignPopulationEnergy(seed_pool)
        
        # # 에너지 기반 풀 선택
        # norm_energy = self.normalizedEnergy(seed_pool.values())

        for population_id, population in seed_pool.items():
            if len(population) == 0:
                continue
            if random.random() <= self.prob:
                self.current_population_idx = population_id
                break
            else:
                self.current_population_idx = 0
                continue
        return seed_pool[self.current_population_idx]
        
    def choose(self, seed_pool:Dict[int, Population]):
        """명세 2.2: 선택된 풀에서 시드 선택"""
        population = self.choose_population(seed_pool)

        self.assignSeedEnergy(population)
        norm_energy = self.normalizedEnergy(population)
        seed = random.choices(population, weights=norm_energy)[0]
        return seed

class MultiPoolFuzzer(AdvancedMutationFuzzer):
    """멀티풀 퍼저 - 명세 1.1~1.4 구현"""     

    def __init__(self, seeds: List[str],
                 mutator,
                 schedule,
                 vuln_callstack) -> None:
        self.vuln_callstack = vuln_callstack
        super().__init__(seeds, mutator, schedule)

    def reset(self):
        """퍼저 초기화"""
        super().reset()
        self.seed_pool = {idx: Population(idx, []) for idx in range(len(self.vuln_callstack), -1, -1)}
        self.seed_pool[len(self.vuln_callstack)] = Population(len(self.vuln_callstack), []) # 초기 풀
        self.coverages_seen = set()

    def create_candidate(self):
        seed = self.schedule.choose(self.seed_pool)
        candidate = seed.data
        trials = min(len(candidate), 1 << random.randint(1, 5))
        for i in range(trials):
            candidate = self.mutator.mutate(candidate)
        return candidate

    
    def get_vuln_depth(self, trace):
        if not trace or not self.vuln_callstack:
            return 0
        
        # 순차 매칭
        depth = 0
        vuln_idx = 0
        for func_name in trace:
            if vuln_idx < len(self.vuln_callstack) and func_name == self.vuln_callstack[vuln_idx]:
                vuln_idx += 1
                depth = vuln_idx
        
        return depth

    def run(self, runner: Runner) -> Tuple[Any, str]:
        """명세 1.1~1.4 구현: 시드풀 관리 로직"""
        result, outcome = super().run(runner)
        
        # 1.1: 시드풀 id로 해당 시드풀의 실행 빈도 수를 업데이트
        self.schedule.population_frequency[self.schedule.current_population_idx] += 1
        
        # 새로운 커버리지 확인 - 우리만의 로직으로 구현
        new_coverage = frozenset(list(runner.coverage()))
        if new_coverage not in self.coverages_seen:
            # 새로운 경로 개척 시드 발견
            self.coverages_seen.add(new_coverage)
            
            # 시드 생성
            seed = Seed(self.inp)
            seed.coverage = new_coverage
            seed.trace = runner.trace()
            
            # 취약 콜스택 도달 깊이 계산 0은 미도달 의미
            vuln_depth = self.get_vuln_depth(seed.trace)
            
            # # 시드를 population에 추가
            # self.population.append(seed)
            
            # 명세 1.2~1.4: 시드풀 분류 로직
            if self.schedule.current_population_idx == 0:
                # 1.2: 시드풀 id가 0이면, (초기|새로운 경로 개척) 시드를 해당 시드풀에 추가
                seed.population_id = vuln_depth

                if seed.population_id not in self.seed_pool:
                    self.seed_pool[seed.population_id] = Population(seed.population_id, [])
                    self.schedule.population_frequency[seed.population_id] = 0
                
                self.seed_pool[seed.population_id].append(seed)
            else:
                # 1.3, 1.4: 시드풀 id가 0이 아닌 경우
                if vuln_depth <= self.schedule.current_population_idx: # 미도달 시,
                    # 1.3: 새로운 경로 개척 시드가 타겟 함수를 실행시키지 않았으면, 해당 시드 풀에 추가
                    seed.population_id = vuln_depth #self.schedule.current_population_idx
                    self.seed_pool[seed.population_id].append(seed)
                else:
                    # 1.4: 새로운 경로 개척 시드가 취약 콜스택에서 다음 함수를 실행시켰으면, 
                    # 해당 인덱스 시드풀에 해당 시드 추가
                    seed.population_id = vuln_depth

                    if seed.population_id not in self.seed_pool:
                        self.seed_pool[seed.population_id] = Population(seed.population_id, [])
                        self.schedule.population_frequency[seed.population_id] = 0

                    self.seed_pool[seed.population_id].append(seed)
        path_id = getPathID(runner.coverage())
        if path_id not in self.schedule.path_frequency:
            self.schedule.path_frequency[path_id] = 1
        else:
            self.schedule.path_frequency[path_id] += 1
        return (result, outcome)

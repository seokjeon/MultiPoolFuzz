#!/usr/bin/env python3
"""
Fuzzing Experiment Runner - 개선된 버전
"""
import os
import random
import pickle
import argparse
import numpy as np
from datetime import datetime
from typing import List, Tuple, Dict, Any
from fuzzingbook.MutationFuzzer import FunctionCoverageRunner
import matplotlib.pyplot as plt
from fuzzingbook.GreyboxFuzzer import Mutator, AFLFastSchedule
from fuzzingbook.Coverage import population_coverage

from targets.crashme import crashme
from fuzzers.MultiPoolFuzz import MultiPoolFunctionTraceRunner, MultiPoolFuzzer, MultiPoolSchedule

# 상수 정의
CRASH_PREFIX = "real_bad!"
DEFAULT_EXECUTIONS = 300000
DEFAULT_TRIALS = 20
DEFAULT_INPUT = "good"
# RANDOM_SEEDS = [273097093550480482149776482929753040226, 267569002556208383620979757021269577302, 335292248450976344323133260575758887029, 69551700919125000279848082007360150532, 78500242504021041846297113499533182560, 20634746167286197924708232685770017847, 17324359437221595872829106219704342953, 63525225033949883996787584239642540529, 142626390565346004960560479902549319164, 78833277801957253724588398618000011407, 21758098795554441431330934222347468527, 104819006138782608182480822927885581410, 132748861923191258575304394985101041296, 64413805161389054448060337523763408502, 267701320028634087811906234736047375815, 302427267042194802963610891649961078484, 307191452906625134555061069388365565562, 214633403920563687046760422408210314363, 238442769315332817429834374203121563276, 12117095097506048635605294237498877689]
RANDOM_SEEDS = None
with open('seeds.txt', 'r') as f:
    RANDOM_SEEDS = [int(line.strip()) for line in f if line.strip()]

VULN_CALLSTACK = ['b1', 'a2', 'd3', 'ex', 'leaf_crash']

class FuzzerTester:
    """퍼저 테스터 클래스"""

    def __init__(self, fuzzer_name: str, prob: float):
        self.fuzzer_name = fuzzer_name.lower()
        self.prob = prob
        self.results = []
    
    def _create_fuzzer_components(self, initial_input: str, target_program, entry_point):
        """퍼저별 컴포넌트 생성"""
        if self.fuzzer_name == "multipoolfuzz-rev-decay":
            schedule = MultiPoolSchedule(VULN_CALLSTACK, 5, self.prob)
            fuzzer = MultiPoolFuzzer([initial_input], Mutator(), schedule, VULN_CALLSTACK)
            runner = MultiPoolFunctionTraceRunner(entry_point, target_program)
        elif self.fuzzer_name == "varfuzz":
            schedule = VarSchedule(5)
            fuzzer = VarFuzzer([initial_input], Mutator(), schedule)
            runner = VarRunner(entry_point)
        else:  # afl
            from fuzzingbook.GreyboxFuzzer import CountingGreyboxFuzzer
            schedule = AFLFastSchedule(5)
            fuzzer = CountingGreyboxFuzzer([initial_input], Mutator(), schedule)
            runner = FunctionCoverageRunner(entry_point)
        
        return fuzzer, schedule, runner
    
    def run_fuzzing(self, initial_input: str, target_program, entry_point, 
                   random_seeds: List[int], execution_num: int) -> None:
        """퍼징 실행"""
        self.results = []
        for seed in random_seeds:
            random.seed(seed)
            fuzzer, schedule, runner = self._create_fuzzer_components(
                initial_input, target_program, entry_point
            )
            fuzzer.runs(runner, trials=execution_num)
            self.results.append((fuzzer, schedule))
    
    def save_results(self, filename: str) -> None:
        """결과 저장"""
        try:
            with open(filename, 'wb') as f:
                pickle.dump(self.results, f)
            print(f"결과가 {filename}에 저장되었습니다.")
        except Exception as e:
            print(f"결과 저장 중 오류: {e}")
    
    def load_results(self, filename: str) -> bool:
        """결과 로드"""
        try:
            with open(filename, 'rb') as f:
                self.results = pickle.load(f)
            print(f"저장된 결과를 {filename}에서 로드했습니다.")
            return True
        except FileNotFoundError:
            print(f"{filename} 파일을 찾을 수 없습니다.")
            return False
        except Exception as e:
            print(f"결과 로드 중 오류: {e}")
            return False

class ExperimentRunner:
    """실험 실행 클래스"""
    
    def __init__(self, args):
        self.args = args
        self.log_dir = f"logs/{datetime.now().strftime('%Y%m%d%H%M%S')}"
        os.makedirs(self.log_dir, exist_ok=True)
        
        # 시드 생성
        self.random_seeds = RANDOM_SEEDS[:args.trials]
        print(f"test count: {len(self.random_seeds)}")
        
    def run_fuzzer(self, fuzzer_name: str, prob) -> FuzzerTester:
        """퍼저 실행"""
        tester = FuzzerTester(fuzzer_name, prob)
        save_file = f"output/{fuzzer_name+':'+str(prob)}_results.pkl"
        
        if not tester.load_results(save_file):
            print(f"{fuzzer_name} 퍼저를 새로 실행합니다...")
            tester.run_fuzzing(self.args.input, crashme, crashme.branching_program, 
                             self.random_seeds, self.args.executions)
        else:
            print(f"저장된 {fuzzer_name} 결과를 사용합니다.")

        tester.save_results(save_file)
        return tester
    
    def average_coverage(self, all_coverages: List[List[int]]) -> List[float]:
        # 각 trial의 길이를 가장 짧은 것에 맞춰 자르기 (또는 패딩)
        min_len = min(len(c) for c in all_coverages)
        trimmed = [c[:min_len] for c in all_coverages]

        # 같은 인덱스끼리 평균 내기
        return np.mean(trimmed, axis=0).tolist()

    def create_coverage_graph(self, testers) -> None:
        """커버리지 그래프 생성"""
        avg_covs = list()
        for idx, tester in enumerate(testers):
            all_results_cov = list()
            for i in range(len(self.random_seeds)):
                fuzzer, _ = tester.results[i]
                _, result_cov = population_coverage(fuzzer.inputs, crashme.branching_program)
                all_results_cov.append(result_cov)

            avg_covs.append(self.average_coverage(all_results_cov))
            plt.plot(avg_covs[-1], label=tester.fuzzer_name+str(tester.prob))

        plt.xlabel("Input #")
        plt.ylabel("Coverage")
        plt.title("Coverage")
        plt.legend()
        
        # # avg_coverage_diff = float(np.mean(np.abs(np.array(avg_cov1[:min_len]) - np.array(avg_cov2[:min_len]))))
        # # print(f"Average absolute coverage difference: {avg_coverage_diff:.4f}")
        # avg_coverage_diff = float(np.mean(np.array(avg_cov2) - np.array(avg_cov1)))
        # print(f"Average coverage difference: {avg_coverage_diff:.4f}")

        # # fuzzer1 기준
        # rel_diff = (avg_coverage_diff/np.mean(avg_cov1)) * 100
        # msg = f"{tester2.fuzzer_name}가 {tester1.fuzzer_name}보다 상대적으로 평균 {avg_coverage_diff:.4f}개의 커버리지\n즉, {rel_diff:.2f}%를 더 탐색했습니다."
        # print(msg)
        
        filename = f"{self.log_dir}/coverage_{datetime.now().strftime('%Y%m%d')}.png"
        plt.savefig(filename)
        plt.savefig("output/coverage.png")
        plt.close()

        # return {
        #     'avg_coverage_diff': avg_coverage_diff,
        #     'rel_diff': rel_diff
        # }
    
    def create_efficiency_graph(self, testers) -> Dict[str, Any]:
        """효율성 그래프 생성"""
        avg_per_fuzzer = []
        cnt_per_fuzzer = []
        labels = []
        found_by = []

        for idx, tester in enumerate(testers):
            fuzzer_crashes = self._count_crashes(tester)
            if fuzzer_crashes['count']: found_by.append(tester.fuzzer_name+str(tester.prob))

            # 바 차트 생성
            labels.append(tester.fuzzer_name[0]+str(tester.prob))
            avg_per_fuzzer.append(fuzzer_crashes['avg'] if fuzzer_crashes['count'] else 0)
            cnt_per_fuzzer.append(fuzzer_crashes['count'])


        msg = f"Found {CRASH_PREFIX}" if found_by else f"Did not find {CRASH_PREFIX}"
        print(f"Result: {msg} : {' '.join(found_by)}")
            
        plt.figure()
        plt.bar(labels, avg_per_fuzzer, width=0.6)
        plt.title("Fuzzer Efficiency Comparison")
        plt.ylabel("# of Inputs until Crash")
        for i, v in enumerate(avg_per_fuzzer):
            plt.text(i, v, f"{v:.1f}", ha="center", va="bottom")
        plt.tight_layout()
        
        filename = f"{self.log_dir}/efficiency_{datetime.now().strftime('%Y%m%d')}.png"
        plt.savefig(filename)
        plt.savefig("output/efficiency.png")
        plt.close()

        # 발견 횟수 그래프  
        plt.figure()
        plt.bar(labels, cnt_per_fuzzer, width=0.6)
        plt.title("Crash Discovery Count")
        plt.ylabel("# of Crashes")
        plt.savefig(f"{self.log_dir}/vuln_found_count_per_fuzzer{datetime.now().strftime('%Y%m%d')}.png")
        plt.close()
        
        return {
            'avg_per_fuzzer': list(zip(labels, avg_per_fuzzer)),
            'cnt_per_fuzzer': list(zip(labels, cnt_per_fuzzer)),
            'found_by': found_by
        }
    
    def _count_crashes(self, tester: FuzzerTester) -> Dict[str, Any]:
        """크래시 개수 및 평균 계산"""
        crash_indices = []
        crash_cnt = 0
        for fuzzer, _ in tester.results:
            crash_idx = next((idx for idx, seed in enumerate(fuzzer.inputs) 
                            if seed.startswith(CRASH_PREFIX)), None)
            if crash_idx is not None:
                crash_cnt += 1
                crash_indices.append(crash_idx)
            else:
                crash_indices.append(self.args.executions)
        
        return {
            'count': crash_cnt,
            'avg': sum(crash_indices) / len(crash_indices) if crash_indices else 0
        }
    
    def save_logs(self, coverage_results: Dict[str, Any], efficiency_result: Dict[str, Any]) -> None:
        """로그 저장"""
        config_data = {
            'execution_time': datetime.now(),
            'trials': len(self.random_seeds),
            'executions': self.args.executions,
            'fuzzers': self.args.fuzzers,
            'entry_point': crashme.branching_program.__name__,
            'log_dir': self.log_dir,
            'coverage_results': coverage_results,
            'efficiency_result': efficiency_result
        }
        
        filename = f"{self.log_dir}/config_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(filename, "w") as f:
            f.write("=== Fuzzing Configuration ===\n")
            for key, value in config_data.items():
                f.write(f"{key}: {value}\n")
                print(f"{key}: {value}")
    
    def run_experiment(self) -> None:
        """실험 실행"""
        # 퍼저 실행
        testers = list()
        for idx, fuzzer in enumerate(self.args.fuzzers):
            fuzzer_name = fuzzer
            prob = None
            if ':' in fuzzer:
                fuzzer_name, prob_str = fuzzer.split(':')
                prob = float(prob_str)
            print(f"Running fuzzer: {fuzzer_name}" + (f" (prob: {prob})" if prob is not None else ""))
            tester = self.run_fuzzer(fuzzer_name, prob)
            testers.append(tester)
        
        # 분석 및 시각화
        coverage_results = self.create_coverage_graph(testers)
        
        # fuzzer1_avg = self._count_crashes(tester1)['avg']
        # fuzzer2_avg = self._count_crashes(tester2)['avg']

        # print(f"{self.args.fuzzer1} 크래시 평균 인덱스: {coverage_results['fuzzer1_first_crash_index']}")
        # print(f"{self.args.fuzzer2} 크래시 평균 인덱스: {coverage_results['fuzzer2_first_crash_index']}")

        efficiency_result = self.create_efficiency_graph(testers)
        self.save_logs(coverage_results, efficiency_result)

def parse_args():
    """명령행 인자 파싱"""
    parser = argparse.ArgumentParser(description='Fuzzing Experiment Runner')
    parser.add_argument('--fuzzers', nargs='+', default=['aflfast', 'multipoolfuzz-rev-decay:0.8'], help='퍼저 선택')
    parser.add_argument('--trials', type=int, default=DEFAULT_TRIALS, 
                       help=f'실행할 시드 개수 (기본값: {DEFAULT_TRIALS})')
    parser.add_argument('--executions', type=int, default=DEFAULT_EXECUTIONS, 
                       help=f'각 퍼저의 실행 횟수 (기본값: {DEFAULT_EXECUTIONS})')
    parser.add_argument('--input', type=str, default=DEFAULT_INPUT, 
                       help=f'초기 입력 (기본값: {DEFAULT_INPUT})')
    return parser.parse_args()

def main():
    """메인 함수"""
    args = parse_args()
    runner = ExperimentRunner(args)
    runner.run_experiment()

if __name__ == "__main__":
    main()

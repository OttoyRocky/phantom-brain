from benchmark_runner import BenchmarkRunner

if __name__ == "__main__":
    print("=" * 50)
    print("Phantom Brain Benchmark Suite")
    print("=" * 50)
    
    runner = BenchmarkRunner()
    runner.run_all()
    
    print("\nResultados guardados en benchmarks/results/")

import threading
import numpy as np
from numba import jit

import threading
import numpy as np
from numba import jit


# 使用Numba JIT编译加速计算
@jit
def calculate_expression(expression, N):
    res = 1
    for i in range(N):
        res *= expression + i
    return res


# 定义计算函数
def calculate_coefficients(expression_values, N):
    global result
    for expression in expression_values:
        expression_result = calculate_expression(expression, N)
        with lock:
            result *= expression_result


if __name__ == "__main__":
    # 定义要计算的 x + b 式子列表，这里使用示例值
    expression_values = list(range(1, 100))

    # 定义变量 N
    N = 1000

    # 定义结果的初始值
    result = 1

    # 定义线程锁，以确保多线程操作时不会出现问题
    lock = threading.Lock()
    # 创建多个线程进行计算
    threads = []
    num_threads = 12  # 根据需要进行调整

    for _ in range(num_threads):
        thread = threading.Thread(target=calculate_coefficients, args=(expression_values, N))
        threads.append(thread)
        thread.start()

    # 等待所有线程完成
    for thread in threads:
        thread.join()

    # 对最终结果进行取模
    modulus = 1000000007
    result %= modulus

    print("Final result:", result)

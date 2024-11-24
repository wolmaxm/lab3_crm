# Функція для видалення дублікатів зі списку
def remove_duplicates(lst):
    no_duplicates = []
    for item in lst:
        if item not in no_duplicates:
            no_duplicates.append(item)
    return no_duplicates

# Функція для перевірки, чи є A підмножиною B
def is_subset(A, B):
    for item in A:
        if item not in B:
            return False
    return True

# Функція для перевірки, чи рівні множини A та B
def is_equal(A, B):
    return is_subset(A, B) and is_subset(B, A)

# Функція для виконання об'єднання двох множин
def union(A, B):
    result = A.copy()
    for item in B:
        if item not in result:
            result.append(item)
    return result

# Функція для виконання перетину двох множин
def intersection(A, B):
    result = []
    for item in A:
        if item in B:
            result.append(item)
    return result

# Функція для виконання різниці двох множин (A - B)
def difference(A, B):
    result = []
    for item in A:
        if item not in B:
            result.append(item)
    return result

# Функція для виконання доповнення множини A відносно універсуму U
def complement(U, A):
    result = []
    for item in U:
        if item not in A:
            result.append(item)
    return result

# Функція для виконання симетричної різниці двох множин
def symmetric_difference(A, B):
    return difference(union(A, B), intersection(A, B))

# Функція для виконання декартового добутку двох множин
def cartesian_product(A, B):
    result = []
    for a in A:
        for b in B:
            result.append((a, b))
    return result

# Функція для створення бітового рядка множини
def create_bit_string(U, A):
    bit_string = []
    for item in U:
        if item in A:
            bit_string.append(1)
        else:
            bit_string.append(0)
    return bit_string

# Функція для перетворення бітового рядка назад у множину
def bit_string_to_set(U, bit_string):
    result = []
    for i in range(len(bit_string)):
        if bit_string[i] == 1:
            result.append(U[i])
    return result

# Головна програма
def main():
    
    # Введення множини A
    A_input = input("Введіть елементи множини A, розділені пробілами: ")
    A_list = A_input.strip().split()
    A = remove_duplicates(A_list)
    print(f"Множина A: {A}")

    # Введення множини B
    B_input = input("Введіть елементи множини B, розділені пробілами: ")
    B_list = B_input.strip().split()
    B = remove_duplicates(B_list)
    print(f"Множина B: {B}")
    
    # Універсум
    U= union(A,B)
    print(f"Універсум U: {U} ")

    # Операції над множинами
    print("\n--- Операції над множинами ---")

    # Об'єднання
    union_result = union(A, B)
    print(f"Об'єднання A та B: {union_result}")

    # Перетин
    intersection_result = intersection(A, B)
    print(f"Перетин A та B: {intersection_result}")

    # Різниця A - B
    difference_result_A_B = difference(A, B)
    print(f"Різниця A - B: {difference_result_A_B}")

    # Різниця B - A
    difference_result_B_A = difference(B, A)
    print(f"Різниця B - A: {difference_result_B_A}")

    # Доповнення A
    complement_result_A = complement(U, A)
    print(f"Доповнення A (відносно U): {complement_result_A}")

    # Доповнення B
    complement_result_B = complement(U, B)
    print(f"Доповнення B (відносно U): {complement_result_B}")

    # Симетрична різниця
    sym_diff_result = symmetric_difference(A, B)
    print(f"Симетрична різниця A та B: {sym_diff_result}")

    # Декартовий добуток
    cartesian_result = cartesian_product(A, B)
    print(f"Декартовий добуток A та B: {cartesian_result}")

    # Перевірка підмножин та рівності
    print("\n--- Перевірка підмножин та рівності ---")
    print(f"Чи є A підмножиною B? {'Так' if is_subset(A, B) else 'Ні'}")
    print(f"Чи є B підмножиною A? {'Так' if is_subset(B, A) else 'Ні'}")
    print(f"Чи рівні множини A та B? {'Так' if is_equal(A, B) else 'Ні'}")

    # Бітове представлення множин
    print("\n--- Бітове представлення множин ---")
    print(f"Універсум U (упорядкований): {U}")
    bit_string_A = create_bit_string(U, A)
    bit_string_B = create_bit_string(U, B)
    print(f"Бітовий рядок множини A: {bit_string_A}")
    print(f"Бітовий рядок множини B: {bit_string_B}")

    # Логічні операції над бітовими рядками
    print("\n--- Логічні операції над бітовими рядками ---")
    # Об'єднання (OR)
    bitwise_union = [bit_string_A[i] | bit_string_B[i] for i in range(len(U))]
    print(f"Бітове об'єднання (A OR B): {bitwise_union}")
    set_union_bitwise = bit_string_to_set(U, bitwise_union)
    print(f"Множина з бітового об'єднання: {set_union_bitwise}")
    print(f"Перевірка з попереднім об'єднанням: {'Коректно' if set_union_bitwise == union_result else 'Некоректно'}")

    # Перетин (AND)
    bitwise_intersection = [bit_string_A[i] & bit_string_B[i] for i in range(len(U))]
    print(f"Бітовий перетин (A AND B): {bitwise_intersection}")
    set_intersection_bitwise = bit_string_to_set(U, bitwise_intersection)
    print(f"Множина з бітового перетину: {set_intersection_bitwise}")
    print(f"Перевірка з попереднім перетином: {'Коректно' if set_intersection_bitwise == intersection_result else 'Некоректно'}")

    # Різниця A - B (A AND NOT B)
    bitwise_difference_A_B = [bit_string_A[i] & (~bit_string_B[i] & 1) for i in range(len(U))]
    print(f"Бітова різниця A - B (A AND NOT B): {bitwise_difference_A_B}")
    set_difference_A_B_bitwise = bit_string_to_set(U, bitwise_difference_A_B)
    print(f"Множина з бітової різниці A - B: {set_difference_A_B_bitwise}")
    print(f"Перевірка з попередньою різницею A - B: {'Коректно' if set_difference_A_B_bitwise == difference_result_A_B else 'Некоректно'}")

    # Симетрична різниця (XOR)
    bitwise_sym_diff = [bit_string_A[i] ^ bit_string_B[i] for i in range(len(U))]
    print(f"Бітова симетрична різниця (A XOR B): {bitwise_sym_diff}")
    set_sym_diff_bitwise = bit_string_to_set(U, bitwise_sym_diff)
    print(f"Множина з бітової симетричної різниці: {set_sym_diff_bitwise}")
    print(f"Перевірка з попередньою симетричною різницею: {'Коректно' if set_sym_diff_bitwise == sym_diff_result else 'Некоректно'}")

if __name__ == "__main__":
    main()

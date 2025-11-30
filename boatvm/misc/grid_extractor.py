#!/usr/bin/env python3

# Extract the exact values from the VM disassembly (addresses 0032-0112)
values = [
    -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, 1.0, -1.0,  # 0032-0040
    4.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0,   # 0041-0049
    -1.0, 2.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0,   # 0050-0058
    -1.0, -1.0, -1.0, 5.0, -1.0, 4.0, -1.0, 7.0, -1.0,     # 0059-0067
    -1.0, 8.0, -1.0, -1.0, -1.0, 3.0, -1.0, -1.0, -1.0,    # 0068-0076
    -1.0, 1.0, -1.0, 9.0, -1.0, -1.0, -1.0, -1.0, 3.0,     # 0077-0085
    -1.0, -1.0, 4.0, -1.0, -1.0, 2.0, -1.0, -1.0, -1.0,    # 0086-0094
    5.0, -1.0, 1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0,    # 0095-0103
    -1.0, -1.0, 8.0, -1.0, 6.0, -1.0, -1.0, -1.0, -1.0     # 0104-0112
]

print(f"Total values: {len(values)}")

# Since these are pushed on a stack, they're in reverse order
# The last pushed value (0112) is at the top of stack (position 0,0)
# The first pushed value (0032) is at the bottom (position 8,8)

# Reverse the order to get the correct grid layout
values.reverse()

# Create 9x9 grid
grid = []
for i in range(9):
    row = []
    for j in range(9):
        val = values[i * 9 + j]
        row.append(int(val) if val != -1.0 else 0)
    grid.append(row)

print("\nSudoku Grid (0 = empty):")
for i in range(9):
    if i % 3 == 0 and i != 0:
        print("------+-------+------")
    for j in range(9):
        if j % 3 == 0 and j != 0:
            print("| ", end="")
        print(f"{grid[i][j]} " if grid[i][j] != 0 else "_ ", end="")
    print()

# Validate the grid
def is_valid_sudoku(grid):
    """Check if the initial grid is valid"""
    def has_duplicates(arr):
        nums = [x for x in arr if x != 0]
        return len(nums) != len(set(nums))
    
    # Check rows
    for row in grid:
        if has_duplicates(row):
            return False, "Invalid row found"
    
    # Check columns  
    for j in range(9):
        col = [grid[i][j] for i in range(9)]
        if has_duplicates(col):
            return False, "Invalid column found"
    
    # Check 3x3 boxes
    for box_row in range(0, 9, 3):
        for box_col in range(0, 9, 3):
            box = []
            for i in range(box_row, box_row + 3):
                for j in range(box_col, box_col + 3):
                    box.append(grid[i][j])
            if has_duplicates(box):
                return False, f"Invalid 3x3 box at ({box_row},{box_col})"
    
    return True, "Valid grid"

valid, msg = is_valid_sudoku(grid)
print(f"\nGrid validation: {msg}")

if valid:
    print("\nGrid as Python array:")
    print("puzzle = [")
    for row in grid:
        print(f"    {row},")
    print("]")
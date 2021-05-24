from os import name

with open('text.txt', 'r') as f:
    f_read = f.read()

print(f_read)

data = 'input message : '

output = data + f_read

print(output)
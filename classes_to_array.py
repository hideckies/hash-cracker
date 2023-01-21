import sys

classes = sys.argv[1]
classes_array = classes.split(",")
print(f"const classes = {classes_array};")
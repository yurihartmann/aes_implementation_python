from my_aes import MyAES

my_aes = MyAES(
    key="65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80"
)
# print(my_aes.keys)
my_aes.encrypty(
    "file_to_encode.txt"
)

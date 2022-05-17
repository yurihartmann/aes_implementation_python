import os
from copy import deepcopy
from typing import List

from constants import SBox, RoundConstant, print_matrix, LTable, ETable


class MyAES:
    rounds_keys: List[List[str]] = []

    def __init__(self, key: str, debug: bool = False):
        self.debug = debug
        self.__load_master_keys(key=key)
        self.__expand_master_key()

    @staticmethod
    def __list_to_matrix(the_list: list) -> List[List[str]]:
        result = [[] for _ in range(4)]
        for i, key in enumerate(the_list):
            byte = hex(int(key))
            result[i // 4].append(byte)

        return result

    @staticmethod
    def __matrix_to_text(matrix: list) -> bytes:
        result = ''
        for i in range(4):
            for j in range(4):
                result += chr(int(matrix[i][j], 16))

        return result.encode()

    def __load_master_keys(self, key):
        keys = key.split(',')

        if len(keys) != 16:
            raise Exception("key invalid")

        self.rounds_keys = self.__list_to_matrix(keys)

    def __expand_master_key(self):
        if self.debug:
            print("**** Chave ****")
            print_matrix(self.rounds_keys)

        num_round = 0
        for i in range(4, 4 * 11):
            if i % 4 == 0:
                # Novo round que passa pelo RoundConstant
                self.new_round(num_round)
                num_round += 1
            else:
                # Proximo round que apenas gera pelo anterior
                self.next_round()

            if (i + 1) % 4 == 0 and self.debug:
                print(f"**** RoundKey={num_round} ****")
                print_matrix(self.rounds_keys[i-3:i+1])

    def new_round(self, num_round):
        new_round = deepcopy(self.rounds_keys[-1])
        new_round.append(new_round.pop(0))

        # Substituição pela tabela SBox
        for i in range(4):
            new_round[i] = hex(SBox[int(new_round[i], 16)])

        # XOR da primeira linha pelo RoundConstant
        for i in range(4):
            if i == 0:
                new_round[0] = hex(int(new_round[0], 16) ^ RoundConstant[num_round])
            else:
                new_round[i] = hex(int(new_round[i], 16) ^ 0x00)

        # XOR das linhas pelas linhas do round anterior
        for i in range(4):
            new_round[i] = hex(int(new_round[i], 16) ^ int(self.rounds_keys[-4][i], 16))

        # Adiciona o round nas chaves
        self.rounds_keys.append(new_round)

    def next_round(self):
        new_round = deepcopy(self.rounds_keys[-1])
        # XOR das linhas pelas linhas do round anterior
        for i in range(4):
            new_round[i] = hex(int(new_round[i], 16) ^ int(self.rounds_keys[-4][i], 16))

        self.rounds_keys.append(new_round)

    @classmethod
    def generate_PKCS5(cls, n: int):
        return [n for _ in range(n)]

    def encrypty(self, file_path):
        # Le o arquivo
        file = open(file_path, mode='rb')
        file_out = open(file_path + ".bin", mode='wb')
        file_size = (os.path.getsize(file_path) / 16) + 1
        # Le os primeiro 16 bytes = 128 bits
        data = file.read(16)
        need_padding = True

        file_size_already_encrypty = 0
        percentage_aux = (100 / file_size)
        percentage = 0

        while data or need_padding:
            # Porcentagem
            file_size_already_encrypty += 1

            percentage_now = int(percentage_aux * file_size_already_encrypty)
            if percentage < percentage_now:
                percentage = percentage_now
                print(percentage_now, "%")

            data = list(data)

            if len(data) < 16:
                need_padding = False
                data += self.generate_PKCS5(16 - len(data))

            # Transforma em matrix
            matrix = self.__list_to_matrix(list(data))

            if self.debug:
                print("**** Texto simples ****")
                print_matrix(matrix)

            encrypty_data = self.__encrypty(matrix)

            file_out.write(
                MyAES.__matrix_to_text(encrypty_data)
            )

            # Le os próximos 16 bytes = 128 bits
            data = file.read(16)

        file.close()
        file_out.close()

    def __encrypty(self, matrix: List[List[str]]):
        # XOR da matrix com primeira round_key
        self.__add_round_key(matrix, self.rounds_keys[:4])

        if self.debug:
            print_matrix(matrix)

        for i in range(1, 10):  # range(1, 10)
            round_key = self.rounds_keys[4 * i: 4 * (i + 1)]
            self.__sub_bytes(matrix)
            self.__shift_rows(matrix)
            matrix = self.__mix_columns(matrix)
            self.__add_round_key(matrix, round_key)

        # Substituição pela tabela SBox
        self.__sub_bytes(matrix)

        # Shift Rows
        self.__shift_rows(matrix)

        # XOR da matrix com ultima round_key
        self.__add_round_key(matrix, self.rounds_keys[-4:])

        return matrix

    @staticmethod
    def __add_round_key(matrix, round_key):
        for i in range(4):
            for j in range(4):
                matrix[i][j] = hex(int(matrix[i][j], 16) ^ int(round_key[i][j], 16))

    @staticmethod
    def __sub_bytes(matrix):
        for i in range(4):
            for j in range(4):
                matrix[i][j] = hex(SBox[int(matrix[i][j], 16)])

    @staticmethod
    def __shift_rows(m):
        m[0][1], m[1][1], m[2][1], m[3][1] = m[1][1], m[2][1], m[3][1], m[0][1]
        m[0][2], m[1][2], m[2][2], m[3][2] = m[2][2], m[3][2], m[0][2], m[1][2]
        m[0][3], m[1][3], m[2][3], m[3][3] = m[3][3], m[0][3], m[1][3], m[2][3]

    @staticmethod
    def __calc_aux_mix_single_column(r, i):
        r = int(r, 16)
        if r == 0 or i == 0:
            return 0

        if r == 1:
            return i

        if i == 1:
            return r

        r_converted = LTable[r]
        i_converted = LTable[i]
        result = r_converted + i_converted

        if result > 255:
            result -= 255

        return ETable[result]

    @staticmethod
    def __mix_single_column(col: list, matrix_multiplier: list):
        list_r = [
            MyAES.__calc_aux_mix_single_column(col[j], matrix_multiplier[j])
            for j in range(4)
        ]

        b = list_r[0] ^ list_r[1] ^ list_r[2] ^ list_r[3]

        return hex(b)

    def __mix_columns(self, matrix) -> List[List]:
        matrix_multiplier = [
            [2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 1, 2, 3],
            [3, 1, 1, 2]
        ]

        new: List[List] = [[None for _ in range(4)] for _ in range(4)]

        for i in range(4):
            for j in range(4):
                new[i][j] = self.__mix_single_column(
                    matrix[i],
                    matrix_multiplier[j]
                )

        return new

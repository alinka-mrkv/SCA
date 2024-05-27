import idautils
import idc
import idaapi
import db


# Получаем адреса всех функций в программе

# flag = 0
# for segment in idautils.Segments():

#     for func in idautils.Functions(idc.get_segm_start(segment), idc.get_segm_end(segment)):

#         for (start, end) in idautils.Chunks(func):

#             # Проходимся по каждой инструкции
#             for instruction in idautils.Heads(start, end):
                
#                 if idc.generate_disasm_line(instruction, 0).startswith("push"):# and idc.is_strlit(idc.print_operand(instruction, 1)):

#                     if "offset" in idc.print_operand(instruction, 0):
#                         print(idc.generate_disasm_line(instruction, 0))
#                         flag = 1
# if flag == 0:
#     print("Nothing")

strings = idautils.Strings()
for string in strings:
    print(string)
    db.execute_postgres_command("INSERT INTO Strings (Str) VALUES ('" + str(string) + "');")


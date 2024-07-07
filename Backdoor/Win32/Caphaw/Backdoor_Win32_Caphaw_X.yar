
rule Backdoor_Win32_Caphaw_X{
	meta:
		description = "Backdoor:Win32/Caphaw.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 8d 45 e0 50 68 90 01 04 6a 00 6a 00 ff 15 90 01 03 00 8b f8 85 ff 74 90 01 01 68 e8 03 00 00 57 ff 15 90 01 03 00 3d 02 01 00 00 74 90 01 01 68 e8 03 00 00 ff 15 90 01 03 00 90 00 } //1
		$a_01_1 = {53 55 8b 6c 24 18 56 8b 74 24 10 57 8b 7c 24 1c 8d 64 24 00 8b ca 83 e1 1f bb 01 00 00 00 d3 e3 85 dd 74 09 8a 0e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Backdoor_Win32_Caphaw_X_2{
	meta:
		description = "Backdoor:Win32/Caphaw.X,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 04 85 c9 89 44 24 08 db 44 24 08 d9 fa db 44 24 04 7d 06 dc 05 90 01 04 de c1 e8 90 01 02 00 00 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 00 00 90 01 01 01 72 c4 90 00 } //2
		$a_03_1 = {85 c0 75 13 8b 45 90 01 01 8b 48 3c 03 c8 51 50 53 e8 90 01 02 ff ff 83 c4 0c 90 09 1c 00 8b 46 3c 8b 4c 90 01 01 54 8b d1 c1 e9 02 8b fb f3 a5 8b ca 83 e1 03 f3 a4 e8 90 01 02 ff ff 90 00 } //1
		$a_03_2 = {8b 53 3c 8b 90 01 02 28 03 90 01 01 83 c4 04 89 90 01 02 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
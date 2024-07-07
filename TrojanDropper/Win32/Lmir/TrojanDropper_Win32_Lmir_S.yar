
rule TrojanDropper_Win32_Lmir_S{
	meta:
		description = "TrojanDropper:Win32/Lmir.S,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {ff d7 8b f0 81 e6 ff 01 00 00 81 c6 00 02 00 00 c1 e6 0a 56 } //2
		$a_01_1 = {2e 64 6c 6c 50 8d 85 } //1
		$a_01_2 = {2e 74 6d 70 50 8d 85 } //1
		$a_03_3 = {6a 03 57 6a 01 68 00 00 00 80 89 38 ff 75 08 ff 15 90 01 04 8b d8 83 fb ff 89 5d 08 0f 84 90 01 04 8b 35 90 01 04 6a 02 57 6a fc 53 ff d6 90 00 } //3
		$a_01_4 = {6a 02 57 6a f8 ff 75 08 ff d6 8d 45 ec 57 50 8d 45 fc 6a 04 50 ff 75 08 ff d3 57 ff 75 08 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3+(#a_01_4  & 1)*3) >=7
 
}

rule Ransom_Win32_Reveton_T{
	meta:
		description = "Ransom:Win32/Reveton.T,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 3b 70 18 75 f9 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 8d 40 08 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 } //10
		$a_01_1 = {52 55 4e 44 4c 4c 33 32 2e 45 58 45 00 00 00 00 ff ff ff ff 0d 00 00 00 72 65 67 6d 6f 6e 73 74 64 2e 6c 6e 6b } //1
		$a_03_2 = {9a 02 00 00 6a 00 6a 04 8d 45 90 01 01 50 53 e8 90 01 04 40 0f 84 90 09 03 00 c7 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=12
 
}
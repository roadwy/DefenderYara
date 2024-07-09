
rule Ransom_Win32_Loktrom{
	meta:
		description = "Ransom:Win32/Loktrom,SIGNATURE_TYPE_PEHSTR_EXT,64 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 8b 15 30 00 00 00 89 55 f8 8b 55 f8 8b 52 0c 8b } //5
		$a_01_1 = {64 8b 05 30 00 00 00 89 45 fc 8b 45 fc 8b 40 0c 89 } //5
		$a_01_2 = {8a 18 33 59 04 88 18 40 4a 75 } //2
		$a_03_3 = {8a 08 8b 5d ?? 33 4b 04 88 08 40 4a 75 } //2
		$a_01_4 = {8a 02 33 46 04 88 02 42 49 75 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}
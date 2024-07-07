
rule Virus_Win32_Sality{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_07_0 = {8a 44 05 00 30 07 90 03 03 02 80 e9 01 fe c9 5e 4e 0f 90 03 05 01 84 90 01 04 e9 85 90 16 fe c2 90 00 } //1
	condition:
		((#a_07_0  & 1)*1) >=1
 
}
rule Virus_Win32_Sality_2{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b dd 33 c9 66 69 c1 90 01 02 d1 e9 2b c1 d1 e1 66 31 84 0d 90 01 02 00 00 41 41 3b ca 74 02 eb e5 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Virus_Win32_Sality_3{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_09_0 = {75 06 2b 0c 24 8d 7d 00 89 14 24 8d 49 ac } //1
		$a_09_1 = {33 db 53 4b 8d 40 73 f7 6c 24 68 52 } //1
		$a_03_2 = {2f 6c 6f 67 6f 90 02 01 2e 67 69 66 90 00 } //1
	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
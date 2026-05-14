
rule Virus_Win32_Sality{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_07_0 = {8a 44 05 00 30 07 (80 e9 01|fe c9) 5e 4e 0f 90 03 05 01 84 ?? ?? ?? ?? e9 85 90 16 fe c2 } //1
	condition:
		((#a_07_0  & 1)*1) >=1
 
}
rule Virus_Win32_Sality_2{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b dd 33 c9 66 69 c1 ?? ?? d1 e9 2b c1 d1 e1 66 31 84 0d ?? ?? 00 00 41 41 3b ca 74 02 eb e5 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Virus_Win32_Sality_3{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_09_0 = {75 06 2b 0c 24 8d 7d 00 89 14 24 8d 49 ac } //1
		$a_09_1 = {33 db 53 4b 8d 40 73 f7 6c 24 68 52 } //1
		$a_03_2 = {2f 6c 6f 67 6f [0-01] 2e 67 69 66 } //1
	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Virus_Win32_Sality_4{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 38 39 2e 31 31 39 2e 36 37 2e 31 35 34 2f 74 65 73 74 6f 35 2f } //http://89.119.67.154/testo5/  2
		$a_80_1 = {68 74 74 70 3a 2f 2f 6b 75 6b 75 74 72 75 73 74 6e 65 74 37 37 37 2e 69 6e 66 6f 2f 68 6f 6d 65 2e 67 69 66 } //http://kukutrustnet777.info/home.gif  2
		$a_80_2 = {68 74 74 70 3a 2f 2f 6b 75 6b 75 74 72 75 73 74 6e 65 74 38 38 38 2e 69 6e 66 6f 2f 68 6f 6d 65 2e 67 69 66 } //http://kukutrustnet888.info/home.gif  2
		$a_80_3 = {68 74 74 70 3a 2f 2f 6b 75 6b 75 74 72 75 73 74 6e 65 74 39 38 37 2e 69 6e 66 6f 2f 68 6f 6d 65 2e 67 69 66 } //http://kukutrustnet987.info/home.gif  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=4
 
}
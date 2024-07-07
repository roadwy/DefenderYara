
rule Backdoor_WinNT_Phdet_A{
	meta:
		description = "Backdoor:WinNT/Phdet.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 7e 4b 54 1a } //1
		$a_01_1 = {68 e0 3c 96 a2 } //1
		$a_01_2 = {68 31 a1 44 bc } //1
		$a_01_3 = {c7 45 f4 6e 74 6f 73 } //1
		$a_01_4 = {8a 1c 38 30 1c 0e } //1
		$a_01_5 = {8b 46 28 03 c3 ff d0 } //1
		$a_01_6 = {ff d0 3d 04 00 00 c0 } //1
		$a_01_7 = {0f 01 4c 24 04 8b 44 24 06 } //1
		$a_01_8 = {f3 aa 8b 02 25 ff ff ff fd 0d 00 00 00 08 89 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}

rule Trojan_WinNT_Alureon_G{
	meta:
		description = "Trojan:WinNT/Alureon.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {bf 54 44 4c 44 } //1
		$a_03_1 = {3d 54 44 4c 44 75 90 01 01 a1 08 03 df ff 90 00 } //1
		$a_03_2 = {ff 71 78 ff b1 b4 00 00 00 e8 90 01 04 6a 54 90 00 } //1
		$a_01_3 = {57 01 00 c0 68 bb 64 0b 73 } //1
		$a_01_4 = {8a d1 02 54 24 0c 30 14 01 41 3b 4c 24 08 72 f0 } //1
		$a_01_5 = {68 96 f7 de b5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}
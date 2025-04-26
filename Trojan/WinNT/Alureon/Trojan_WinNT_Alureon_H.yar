
rule Trojan_WinNT_Alureon_H{
	meta:
		description = "Trojan:WinNT/Alureon.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 54 44 4c 44 } //1 hTDLD
		$a_01_1 = {68 96 f7 de b5 } //1
		$a_03_2 = {57 01 00 c0 8b ?? ?? 68 1b 50 8a fd } //1
		$a_03_3 = {54 44 4c 4e a1 08 03 df ff 90 09 02 00 c7 } //1
		$a_01_4 = {8a 54 24 0c 8b 44 24 04 03 c1 30 10 fe c2 41 3b 4c 24 08 72 ef } //1
		$a_01_5 = {39 16 74 14 8b 03 0b 43 04 75 2d 8b fe 32 c0 b9 00 04 00 00 f3 aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}
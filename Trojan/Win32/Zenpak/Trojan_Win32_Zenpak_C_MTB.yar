
rule Trojan_Win32_Zenpak_C_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_C_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {75 65 76 65 72 79 34 64 69 76 69 64 65 64 67 72 65 61 74 68 65 72 62 } //1 uevery4dividedgreatherb
		$a_01_1 = {79 6d 48 69 6d 74 76 50 67 61 74 68 65 72 69 6e 67 67 72 65 61 74 } //1 ymHimtvPgatheringgreat
		$a_01_2 = {6e 79 69 65 6c 64 69 6e 67 41 75 73 79 64 69 76 69 64 65 } //1 nyieldingAusydivide
		$a_01_3 = {36 53 74 61 72 73 73 65 61 47 73 75 62 64 75 65 6a } //1 6StarsseaGsubduej
		$a_01_4 = {58 72 75 6c 65 34 4b 67 69 76 65 6e 6c 69 67 68 74 56 6f 69 64 79 69 65 6c 64 69 6e 67 57 } //1 Xrule4KgivenlightVoidyieldingW
		$a_01_5 = {6b 6d 61 6b 65 67 69 76 65 6e 79 37 66 } //1 kmakegiveny7f
		$a_01_6 = {73 6f 6f 76 65 72 6b 69 6e 66 6f 77 6c } //1 sooverkinfowl
		$a_01_7 = {77 65 72 65 69 64 6f 6d 69 6e 69 6f 6e } //1 wereidominion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
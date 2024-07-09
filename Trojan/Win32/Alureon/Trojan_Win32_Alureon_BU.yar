
rule Trojan_Win32_Alureon_BU{
	meta:
		description = "Trojan:Win32/Alureon.BU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 44 49 50 47 ?? 32 4c 44 54 } //2
		$a_03_1 = {76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1 } //2
		$a_01_2 = {c7 45 f0 43 d2 0e 53 } //1
		$a_01_3 = {63 6c 6b 2e 70 68 70 00 } //1
		$a_01_4 = {69 6e 66 6f 62 69 6e 2e 70 68 70 } //1 infobin.php
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
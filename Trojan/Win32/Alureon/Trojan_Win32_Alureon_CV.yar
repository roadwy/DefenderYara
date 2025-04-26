
rule Trojan_Win32_Alureon_CV{
	meta:
		description = "Trojan:Win32/Alureon.CV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1 } //3
		$a_03_1 = {68 44 49 42 47 ?? 32 4c 44 54 } //3
		$a_01_2 = {68 44 49 41 47 } //1 hDIAG
		$a_01_3 = {68 54 4e 43 47 } //1 hTNCG
		$a_01_4 = {2f 61 64 63 2e 70 68 70 } //1 /adc.php
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
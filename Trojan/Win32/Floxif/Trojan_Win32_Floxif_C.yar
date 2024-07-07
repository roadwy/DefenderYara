
rule Trojan_Win32_Floxif_C{
	meta:
		description = "Trojan:Win32/Floxif.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 46 03 3c 01 8d 46 04 74 90 01 01 8a 08 f6 d1 84 c9 88 08 90 00 } //1
		$a_01_1 = {c6 45 a0 e9 03 fa 8b c7 8b 08 89 4d c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
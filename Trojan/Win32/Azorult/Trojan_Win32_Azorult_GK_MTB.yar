
rule Trojan_Win32_Azorult_GK_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {e9 14 01 00 00 56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00 } //1
		$a_02_1 = {8b 4d 08 33 d2 8b c6 f7 75 0c 8a 04 0a ba 90 01 02 00 00 30 04 37 46 3b f2 72 e9 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
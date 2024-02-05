
rule Trojan_Win32_Lazy_GMF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6a 37 59 33 d2 8b c3 f7 f1 80 c2 34 30 54 1c 19 43 83 fb 0e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lazy_GMF_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 55 d8 c7 45 90 01 01 bc 7e 06 32 c7 45 90 01 01 b8 7e 06 32 66 89 45 e4 c7 45 90 01 01 64 3b 05 32 c7 45 90 01 01 00 00 01 00 c7 45 90 01 01 ec 7e 06 32 c7 45 90 01 01 e8 7e 06 32 66 89 45 f8 39 4d 08 0f 85 90 00 } //0a 00 
		$a_03_1 = {ac ae 06 32 c7 85 90 01 04 a8 ae 06 32 66 89 85 90 01 04 c7 85 90 01 04 0c 5b 05 32 c7 85 90 01 04 e0 ae 06 32 c7 85 90 01 04 dc ae 06 32 66 89 85 90 00 } //01 00 
		$a_80_2 = {47 41 32 52 5a 4e 62 6d } //GA2RZNbm  00 00 
	condition:
		any of ($a_*)
 
}
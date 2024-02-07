
rule Trojan_Win32_DllInject_MA_MTB{
	meta:
		description = "Trojan:Win32/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 50 72 6f } //03 00  OnePro
		$a_01_1 = {54 77 6f 50 72 6f } //03 00  TwoPro
		$a_01_2 = {54 68 72 50 72 6f } //03 00  ThrPro
		$a_01_3 = {65 73 74 61 74 65 2e 64 6c 6c } //01 00  estate.dll
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_DllInject_MA_MTB_2{
	meta:
		description = "Trojan:Win32/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 56 d8 e7 d8 d8 d8 c9 d8 e2 d8 ed 8a 0a d8 cd d8 c1 8a 0e d8 c3 d8 df d8 e6 8a 12 d8 cd d8 c2 d8 c8 d8 e1 d8 df d8 ea d8 e2 d8 d1 d8 ce d8 e1 } //01 00 
		$a_01_1 = {d8 da d8 c7 d8 c4 8a 13 eb 42 d8 cf d8 c8 d8 c6 d8 c5 d8 e7 d8 dd d8 d1 d8 eb d8 c8 88 0c d8 e6 d8 c8 89 11 d8 c6 d8 d1 d8 dc 88 0f d8 cb d8 c0 } //00 00 
	condition:
		any of ($a_*)
 
}
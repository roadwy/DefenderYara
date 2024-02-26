
rule Trojan_Win32_Berbew_AB_MTB{
	meta:
		description = "Trojan:Win32/Berbew.AB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb 9b 3a f9 1f 89 d8 29 d8 89 c3 81 eb e9 27 00 00 b8 42 54 00 00 f7 e3 } //01 00 
		$a_01_1 = {81 f3 b9 27 00 00 81 c3 7a 44 00 00 89 d8 29 d8 89 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
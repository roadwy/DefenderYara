
rule Trojan_Win32_Dridex_AGC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AGC!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 5c 24 33 89 44 24 2c 88 d8 f6 e3 88 84 24 b3 00 00 00 8b 74 24 2c 31 f1 89 8c 24 98 } //0a 00 
		$a_01_1 = {c0 88 84 24 b3 00 00 00 b0 74 8a 4c 24 33 28 c8 8b 54 24 48 8b 74 24 5c 88 84 24 b3 } //00 00 
	condition:
		any of ($a_*)
 
}
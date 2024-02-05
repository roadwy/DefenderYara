
rule Trojan_Win32_CoinStealer_BC_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 83 f1 3c 81 e9 90 01 04 03 cf 81 e9 90 01 04 89 4d 90 00 } //01 00 
		$a_03_1 = {2b c7 83 c0 4c 81 f0 90 01 04 2b c6 33 05 90 01 04 81 e8 90 01 04 03 05 90 01 04 89 45 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_CoinStealer_CA_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {32 c1 32 c1 2a c1 34 90 01 01 34 90 01 01 2a c1 c0 c0 90 01 01 2a c1 aa 4a 0f 85 90 00 } //01 00 
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
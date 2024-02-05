
rule Trojan_Win32_CoinMiner_DM_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.DM!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c } //01 00 
		$a_01_1 = {63 72 79 70 74 6f 6e 69 67 68 74 } //01 00 
		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 70 6f 6f 6c 2e 6d 69 6e 65 78 6d 72 2e 63 6f 6d 3a 38 30 20 2d 75 } //01 00 
		$a_01_3 = {62 6c 61 63 6b 6d 6f 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
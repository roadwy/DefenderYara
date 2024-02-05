
rule Trojan_Win32_CoinMiner_QS_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 64 6c 6c 68 6f 74 2e 65 78 65 20 2f 66 } //01 00 
		$a_01_1 = {64 6c 6c 68 6f 74 2e 65 78 65 20 2d 2d 61 75 74 6f 20 2d 2d 61 6e 79 20 2d 2d 66 6f 72 65 76 65 72 20 2d 2d 6b 65 65 70 61 6c 69 76 65 } //01 00 
		$a_03_2 = {2d 2d 76 61 72 69 61 74 69 6f 6e 20 32 30 20 2d 2d 6c 6f 77 20 2d 6f 20 90 02 20 20 2d 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_CoinMiner_RH_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.RH!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 34 72 6d 30 6e 2e 68 61 64 2e 73 75 } //01 00  g4rm0n.had.su
		$a_01_1 = {63 6f 6e 66 69 67 2e 74 78 74 } //01 00  config.txt
		$a_01_2 = {6e 76 69 64 69 61 2e 74 78 74 } //01 00  nvidia.txt
		$a_01_3 = {62 69 74 63 6f 69 6e 63 61 73 68 } //00 00  bitcoincash
	condition:
		any of ($a_*)
 
}
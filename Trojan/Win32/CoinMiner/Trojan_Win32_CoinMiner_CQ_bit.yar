
rule Trojan_Win32_CoinMiner_CQ_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.CQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 55 70 64 61 74 65 72 2e 65 78 65 20 2d 6c 20 6c 75 63 6b 70 6f 6f 6c 2e 6f 72 67 } //00 00 
	condition:
		any of ($a_*)
 
}
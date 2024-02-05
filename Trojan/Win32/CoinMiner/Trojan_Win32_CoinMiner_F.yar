
rule Trojan_Win32_CoinMiner_F{
	meta:
		description = "Trojan:Win32/CoinMiner.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 5c 4a 61 76 61 0d 0a 73 76 63 68 6f 73 74 20 2d 75 20 90 02 20 20 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
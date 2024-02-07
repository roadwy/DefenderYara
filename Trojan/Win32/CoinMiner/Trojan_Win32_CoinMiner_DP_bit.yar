
rule Trojan_Win32_CoinMiner_DP_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.DP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 74 6b 69 75 62 6c 75 64 6b 69 2e 62 69 74 } //01 00  utkiubludki.bit
		$a_03_1 = {69 20 2d 4f 20 90 02 80 3a 78 20 2d 6b 20 2d 2d 6d 61 78 2d 63 70 75 2d 75 73 61 67 65 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_CoinMiner_SC_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.SC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 1b 8b 4d 90 01 01 03 4d 90 01 01 0f be 11 8b 45 90 01 01 83 c0 55 33 d0 8b 4d 90 01 01 03 4d 90 01 01 88 11 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 89 4d 90 01 01 0f be 45 08 8b 4d 0c 83 c1 55 33 c1 8b e5 5d 90 00 } //01 00 
		$a_01_2 = {64 a1 18 00 00 00 8b 40 30 80 78 02 00 } //00 00 
	condition:
		any of ($a_*)
 
}
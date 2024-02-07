
rule Trojan_Win32_CoinMiner_QK_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 70 6c 6f 72 65 73 2e 65 78 65 20 2d 61 20 63 72 79 70 74 6f 6e 69 67 68 74 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a } //01 00  explores.exe -a cryptonight -o stratum+tcp:
		$a_00_1 = {a3 d6 b9 cd da bf f3 } //01 00 
		$a_00_2 = {41 75 74 6f 52 75 6e 41 70 70 2e 76 62 73 } //00 00  AutoRunApp.vbs
	condition:
		any of ($a_*)
 
}
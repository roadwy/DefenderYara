
rule Trojan_Win64_CoinMiner_QZ_bit{
	meta:
		description = "Trojan:Win64/CoinMiner.QZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 } //02 00  shutdown -s -t
		$a_01_1 = {6f 70 65 6e 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //02 00 
		$a_01_2 = {b9 4d 5a 00 00 66 39 08 75 33 48 63 48 3c 48 03 c8 81 39 50 45 00 00 } //02 00 
		$a_03_3 = {48 63 ca 8d 42 90 01 01 ff c2 30 44 0c 30 83 fa 0c 72 ef 90 00 } //01 00 
		$a_03_4 = {48 63 ca 8a c2 41 2a c1 41 03 d7 30 44 0c 90 01 01 83 fa 90 01 01 72 ec 90 00 } //01 00 
		$a_03_5 = {48 63 ca 41 8d 04 11 41 03 d7 30 44 0c 90 01 01 83 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
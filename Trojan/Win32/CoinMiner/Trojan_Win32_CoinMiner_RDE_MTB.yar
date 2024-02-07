
rule Trojan_Win32_CoinMiner_RDE_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 36 36 5f 52 61 75 6d 57 69 74 68 4d 65 5f 36 36 36 } //01 00  666_RaumWithMe_666
		$a_01_1 = {57 69 6e 44 44 4b } //01 00  WinDDK
		$a_01_2 = {74 6f 6f 6c 73 2f 72 65 67 77 72 69 74 65 2e 72 61 75 6d 5f 65 6e 63 72 79 70 74 65 64 } //01 00  tools/regwrite.raum_encrypted
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4b 6f 6e 71 75 65 72 6f 72 2f 34 2e 33 3b 20 4c 69 6e 75 78 29 20 4b 48 54 4d 4c 2f 34 2e 33 2e 35 20 28 6c 69 6b 65 20 47 65 63 6b 6f 29 } //01 00  Mozilla/5.0 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)
		$a_01_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d } //01 00  SELECT * FROM
		$a_01_5 = {41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //01 00  AntiVirusProduct
		$a_01_6 = {57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72 } //00 00  Win32_VideoController
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Vidar_CLS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 d8 23 da c1 e8 90 01 01 33 04 90 01 05 83 c1 90 01 01 83 ef 90 01 01 4e 90 00 } //05 00 
		$a_03_1 = {0f b6 31 33 f0 23 f2 c1 e8 90 01 01 33 04 90 01 05 41 4f 75 90 00 } //01 00 
		$a_81_2 = {47 65 72 6f 57 61 6c 6c 65 74 } //01 00  GeroWallet
		$a_81_3 = {50 6f 6e 74 65 6d 20 57 61 6c 6c 65 74 } //01 00  Pontem Wallet
		$a_81_4 = {50 65 74 72 61 20 57 61 6c 6c 65 74 } //01 00  Petra Wallet
		$a_81_5 = {4d 61 72 74 69 61 6e 20 57 61 6c 6c 65 74 } //01 00  Martian Wallet
		$a_81_6 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //01 00  HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_81_7 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //01 00  Select * From Win32_OperatingSystem
		$a_81_8 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //00 00  Select * From AntiVirusProduct
	condition:
		any of ($a_*)
 
}
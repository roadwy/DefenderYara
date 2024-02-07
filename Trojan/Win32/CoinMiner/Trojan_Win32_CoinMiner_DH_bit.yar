
rule Trojan_Win32_CoinMiner_DH_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.DH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 37 44 53 56 63 4c 45 31 6a 46 7a 35 75 65 67 35 59 34 35 6b 33 42 6d 36 68 72 36 35 76 33 74 65 70 } //01 00  D7DSVcLE1jFz5ueg5Y45k3Bm6hr65v3tep
		$a_01_1 = {2d 61 20 79 65 73 63 72 79 70 74 20 2d 6f } //01 00  -a yescrypt -o
		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 79 65 73 63 72 79 70 74 2e 6e 61 2e 6d 69 6e 65 2e 7a 70 6f 6f 6c 2e 63 61 3a 36 32 33 33 } //00 00  stratum+tcp://yescrypt.na.mine.zpool.ca:6233
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CoinMiner_DH_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.DH!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 74 00 72 00 61 00 74 00 75 00 6d 00 20 00 2b 00 20 00 74 00 63 00 70 00 3a 00 } //01 00  stratum + tcp:
		$a_03_1 = {88 04 30 8b 8e 90 01 04 8b c1 99 f7 fb 8a 04 3a 88 84 0e 90 09 0d 00 8b 86 90 01 04 48 89 86 90 00 } //01 00 
		$a_03_2 = {0f b6 04 31 30 02 8b 86 90 01 04 8b 8e 90 01 04 0f b6 04 30 30 04 31 8b 86 90 01 04 8b 8e 90 01 04 0f b6 04 30 30 04 31 90 00 } //01 00 
		$a_03_3 = {40 70 69 6e 67 20 2d 6e 90 02 10 31 32 37 2e 30 2e 30 2e 31 26 64 65 6c 90 00 } //01 00 
		$a_01_4 = {42 00 79 00 70 00 61 00 73 00 73 00 55 00 61 00 63 00 } //01 00  BypassUac
		$a_01_5 = {43 00 6f 00 70 00 79 00 4d 00 6f 00 6e 00 65 00 72 00 6f 00 54 00 6f 00 44 00 73 00 74 00 50 00 61 00 74 00 68 00 20 00 66 00 61 00 69 00 6c 00 64 00 2c 00 20 00 25 00 73 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 66 00 61 00 69 00 6c 00 64 00 20 00 62 00 79 00 3a 00 25 00 64 00 } //00 00  CopyMoneroToDstPath faild, %s delete faild by:%d
	condition:
		any of ($a_*)
 
}
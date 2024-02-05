
rule TrojanDropper_Win32_Zegost_W{
	meta:
		description = "TrojanDropper:Win32/Zegost.W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {50 ff d6 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 8b 75 fc 81 be 90 01 02 00 00 20 01 00 00 8d 46 10 50 74 0d 68 90 01 04 e8 90 01 02 ff ff 59 eb 05 90 00 } //01 00 
		$a_01_1 = {5b 25 30 32 64 2f 25 30 32 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 28 25 73 29 } //01 00 
		$a_01_2 = {47 6c 6f 62 61 6c 5c 47 68 30 73 74 20 25 64 00 } //01 00 
		$a_01_3 = {5c 5c 2e 5c 52 45 53 53 44 54 44 4f 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_KQ{
	meta:
		description = "PWS:Win32/OnLineGames.KQ,SIGNATURE_TYPE_PEHSTR_EXT,16 00 13 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {32 ca 32 cb 80 f1 } //0a 00 
		$a_01_1 = {32 ca 32 0e 80 f1 } //01 00 
		$a_01_2 = {32 ca 66 0f a3 ee 32 cb } //03 00 
		$a_01_3 = {5c 44 66 4c 6f 67 2e 69 6e 69 00 } //03 00 
		$a_01_4 = {5c 46 46 4c 6f 67 2e 69 6e 69 00 } //03 00 
		$a_01_5 = {5c 47 61 6d 65 4c 6f 67 2e 69 6e 69 00 } //03 00 
		$a_01_6 = {5c 68 61 6e 67 61 6d 65 2e 69 6e 69 00 } //03 00 
		$a_01_7 = {5c 4c 75 6f 71 69 4c 6f 67 2e 69 6e 69 00 } //03 00 
		$a_01_8 = {5c 54 69 61 6e 79 69 4c 6f 67 2e 69 6e 69 00 } //03 00 
		$a_01_9 = {26 6c 6f 67 69 6e 5f 69 6e 66 6f 35 3d 00 } //00 00  氦杯湩楟普㕯=
	condition:
		any of ($a_*)
 
}
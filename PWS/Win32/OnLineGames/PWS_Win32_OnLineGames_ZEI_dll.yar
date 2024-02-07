
rule PWS_Win32_OnLineGames_ZEI_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZEI!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {f3 ab 66 ab c6 45 90 01 01 78 c6 45 90 01 01 70 c6 45 90 01 01 6c c6 45 90 01 01 6f c6 45 90 01 01 72 c6 45 90 01 01 65 c6 45 90 01 01 72 c6 45 90 01 01 2e 90 00 } //01 00 
		$a_01_1 = {64 62 72 25 30 32 78 2a 2e 74 73 70 00 } //01 00 
		$a_01_2 = {64 6d 64 62 63 63 66 64 61 6f 69 67 61 6c 6b 67 61 } //01 00  dmdbccfdaoigalkga
		$a_03_3 = {5f 72 65 67 61 6d 6c 65 5f 25 30 38 64 5f 90 09 0d 00 00 67 62 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
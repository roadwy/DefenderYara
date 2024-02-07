
rule PWS_Win32_OnLineGames_ZDV_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZDV!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 09 60 90 61 90 90 6a 01 eb 07 60 90 61 90 90 6a 00 e8 } //01 00 
		$a_01_1 = {8b c6 33 d2 b9 60 00 00 00 bb 03 00 00 00 f7 f1 8b c6 8b ca 33 d2 f7 f3 8a 1c 3e 32 ca 32 cb 80 f1 95 88 0c 3e 46 3b f5 72 d6 } //01 00 
		$a_01_2 = {2f 6d 69 62 61 6f 2e 61 73 70 } //01 00  /mibao.asp
		$a_01_3 = {25 73 3f 61 63 74 3d 26 64 31 30 3d 25 73 26 64 38 30 3d 25 64 } //01 00  %s?act=&d10=%s&d80=%d
		$a_01_4 = {3f 64 31 30 3d 25 73 26 64 31 31 3d 25 73 26 64 30 30 3d 25 73 26 64 30 31 3d 25 73 26 64 32 32 3d 25 73 26 64 33 32 3d 25 73 26 64 37 30 3d 25 64 26 64 39 30 3d 25 64 } //00 00  ?d10=%s&d11=%s&d00=%s&d01=%s&d22=%s&d32=%s&d70=%d&d90=%d
	condition:
		any of ($a_*)
 
}
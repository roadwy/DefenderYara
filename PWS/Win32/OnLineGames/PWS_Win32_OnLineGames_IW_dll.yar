
rule PWS_Win32_OnLineGames_IW_dll{
	meta:
		description = "PWS:Win32/OnLineGames.IW!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 40 1f 00 00 e8 90 01 02 ff ff a1 f8 c3 40 00 80 38 01 0f 84 90 01 02 ff ff 33 c0 90 00 } //01 00 
		$a_01_1 = {64 4e 6c 41 75 4e 63 68 45 72 2e 65 78 45 } //01 00  dNlAuNchEr.exE
		$a_01_2 = {43 36 2d 38 30 2d 43 44 2d 30 30 2d 30 30 2d 30 30 2d 30 31 2d } //01 00  C6-80-CD-00-00-00-01-
		$a_01_3 = {06 48 61 63 6b 65 72 90 } //00 00 
	condition:
		any of ($a_*)
 
}
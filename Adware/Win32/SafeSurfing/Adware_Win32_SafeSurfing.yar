
rule Adware_Win32_SafeSurfing{
	meta:
		description = "Adware:Win32/SafeSurfing,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6d 72 5f 53 75 72 66 54 69 6d 65 72 } //01 00  tmr_SurfTimer
		$a_01_1 = {54 75 54 6f 72 72 65 6e 74 53 65 72 76 69 63 65 } //01 00  TuTorrentService
		$a_03_2 = {43 4d 44 54 6f 53 65 72 76 90 01 11 53 65 6c 66 90 01 09 03 43 4d 44 90 01 0a 4d 73 67 90 00 } //01 00 
		$a_01_3 = {61 64 32 2e 70 68 70 3f 61 64 3d 61 64 73 26 73 3d } //01 00  ad2.php?ad=ads&s=
		$a_01_4 = {52 61 6e 64 31 30 30 74 6f 39 39 39 } //01 00  Rand100to999
		$a_01_5 = {6a 65 74 73 77 61 70 2e 63 6f 6d } //00 00  jetswap.com
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_SafeSurfing_2{
	meta:
		description = "Adware:Win32/SafeSurfing,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {67 00 76 00 75 00 6d 00 3d 00 31 00 2d 00 66 00 6f 00 32 00 6c 00 65 00 71 00 6e 00 76 00 60 00 71 00 2a 00 66 00 6b 00 6b 00 34 00 73 00 7a 00 68 00 2b 00 6d 00 63 00 6f 00 41 00 6c 00 74 00 74 00 6e 00 40 00 32 00 2d 00 68 00 6c 00 2d 00 67 00 62 00 72 00 75 00 73 00 61 00 75 00 2c 00 66 00 72 00 6e 00 30 00 70 00 72 00 64 00 2b 00 6c 00 6a 00 6b 00 3f 00 } //05 00  gvum=1-fo2leqnv`q*fkk4szh+mcoAlttn@2-hl-gbrusau,frn0prd+ljk?
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 6f 00 2e 00 6a 00 65 00 74 00 73 00 77 00 61 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 73 00 66 00 6c 00 61 00 6e 00 67 00 2e 00 70 00 68 00 70 00 3f 00 69 00 74 00 3d 00 34 00 38 00 39 00 33 00 34 00 37 00 33 00 } //03 00  http://go.jetswap.com/ssflang.php?it=4893473
		$a_01_2 = {53 61 66 65 53 75 72 66 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  SafeSurf.Resources.resources
	condition:
		any of ($a_*)
 
}
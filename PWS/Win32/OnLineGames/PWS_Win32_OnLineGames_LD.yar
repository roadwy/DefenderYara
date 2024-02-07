
rule PWS_Win32_OnLineGames_LD{
	meta:
		description = "PWS:Win32/OnLineGames.LD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 65 78 74 3d 47 41 4d 45 51 55 41 4e 7c } //01 00  Text=GAMEQUAN|
		$a_01_1 = {72 75 4e 64 4c 6c 33 32 2e 45 78 45 } //01 00  ruNdLl32.ExE
		$a_01_2 = {73 63 69 76 69 73 61 74 2e 68 6c 70 } //01 00  scivisat.hlp
		$a_01_3 = {64 72 41 47 6f 6e 6e 65 53 74 2e 65 58 65 } //01 00  drAGonneSt.eXe
		$a_01_4 = {64 4e 6c 41 75 4e 63 68 45 72 2e 65 78 45 } //00 00  dNlAuNchEr.exE
	condition:
		any of ($a_*)
 
}
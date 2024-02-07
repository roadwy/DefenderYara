
rule TrojanDownloader_BAT_Stevic_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Stevic.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 63 00 72 00 65 00 65 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 70 00 77 00 2f 00 90 02 30 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_1 = {73 00 63 00 72 00 65 00 65 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 70 00 77 00 2f 00 69 00 70 00 32 00 2e 00 70 00 68 00 70 00 3f 00 65 00 78 00 3d 00 } //01 00  screenhost.pw/ip2.php?ex=
		$a_01_2 = {53 00 74 00 65 00 61 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //00 00  SteamService
	condition:
		any of ($a_*)
 
}
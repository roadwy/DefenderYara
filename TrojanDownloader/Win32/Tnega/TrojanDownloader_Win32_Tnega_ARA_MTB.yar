
rule TrojanDownloader_Win32_Tnega_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tnega.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 44 3d e8 6a 01 8d 4d f0 51 68 90 01 04 88 45 f0 e8 90 01 04 88 44 3d e8 47 83 ff 04 7c df 90 00 } //02 00 
		$a_01_1 = {61 48 52 30 63 44 6f 76 4c 32 52 33 4c 6a 6c 6a 61 57 52 6a 4c 6d 4e 75 4c 32 4a 35 5a 54 41 77 4d 53 35 69 61 57 34 3d } //00 00  aHR0cDovL2R3LjljaWRjLmNuL2J5ZTAwMS5iaW4=
	condition:
		any of ($a_*)
 
}
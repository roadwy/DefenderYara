
rule TrojanDownloader_MacOS_SAgnt_AK_MTB{
	meta:
		description = "TrojanDownloader:MacOS/SAgnt.AK!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 8d 05 0b 54 00 00 48 89 e1 48 89 01 c7 41 20 01 00 00 00 48 c7 41 18 e6 33 00 00 c7 41 10 02 00 00 00 48 c7 41 08 a9 00 00 00 48 8d 3d da 52 00 00 48 8d 0d 99 53 00 00 ba 0b 00 00 00 89 d6 ba 36 00 00 00 41 89 d0 ba 02 00 00 00 89 95 34 fe ff ff 44 8b 8d 34 fe ff ff } //01 00 
		$a_00_1 = {48 8d 05 a7 54 00 00 48 89 e1 48 89 01 c7 41 20 01 00 00 00 48 c7 41 18 e1 33 00 00 c7 41 10 02 00 00 00 48 c7 41 08 a9 00 00 00 48 8d 3d 76 53 00 00 48 8d 0d 25 55 00 00 ba 0b 00 00 00 89 d6 ba 27 00 00 00 41 89 d0 ba 02 00 00 00 89 95 44 fe ff ff 44 8b 8d 44 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
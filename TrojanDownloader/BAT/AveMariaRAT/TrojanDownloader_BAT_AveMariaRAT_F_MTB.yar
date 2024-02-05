
rule TrojanDownloader_BAT_AveMariaRAT_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 59 d2 9c 00 07 17 58 0b 07 7e 90 01 01 00 00 04 8e 69 fe 90 01 01 0c 08 90 0a 7a 00 20 90 01 03 00 28 90 01 01 00 00 0a 00 73 90 01 01 00 00 0a 0a 06 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 80 90 01 01 00 00 04 16 0b 2b 90 01 01 00 7e 90 01 01 00 00 04 07 7e 90 01 01 00 00 04 07 91 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
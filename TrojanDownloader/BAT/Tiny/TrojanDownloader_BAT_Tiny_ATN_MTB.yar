
rule TrojanDownloader_BAT_Tiny_ATN_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a2 08 1f 2a 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2b 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2c 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2d 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2e 1f 90 01 01 8c 07 00 00 01 a2 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
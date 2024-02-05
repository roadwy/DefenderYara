
rule TrojanDownloader_BAT_BitRAT_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 04 06 91 20 a0 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 90 01 01 00 00 04 8e 69 fe 04 0b 07 2d 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}
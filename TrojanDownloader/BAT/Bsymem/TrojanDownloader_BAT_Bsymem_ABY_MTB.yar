
rule TrojanDownloader_BAT_Bsymem_ABY_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bsymem.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 15 00 00 0a 0a 16 0b 2b 19 06 03 07 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 07 18 58 0b 07 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
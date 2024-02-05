
rule TrojanDownloader_BAT_Heracles_CXF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.CXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 0a 25 18 6f 0c 00 00 0a 25 18 6f 0d 00 00 0a 25 02 6f 0e 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_BAT_Tiny_MVD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.MVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 28 08 00 00 0a 07 6f 09 00 00 0a 6f 0a 00 00 0a 0c } //01 00 
		$a_00_1 = {61 6c 6c 73 74 61 72 70 72 69 76 61 74 65 2e 6e 65 74 } //00 00  allstarprivate.net
	condition:
		any of ($a_*)
 
}
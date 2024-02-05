
rule TrojanDownloader_BAT_AsyncRAT_SP_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {fe 09 07 00 7b 09 00 00 04 6f 0a 00 00 0a fe 09 03 00 71 09 00 00 01 6f 0b 00 00 0a 26 00 fe 09 05 00 71 03 00 00 01 20 01 00 00 00 58 fe 0e 00 00 fe 09 05 00 fe 0c 00 00 81 03 00 00 01 fe 09 05 00 71 03 00 00 01 fe 09 04 00 71 03 00 00 01 fe 02 20 00 00 00 00 fe 01 fe 0e 01 00 fe 09 06 00 fe 0c 01 00 81 14 00 00 01 fe 09 06 00 71 14 00 00 01 3a 0a 00 00 00 20 00 00 00 00 38 06 00 00 00 00 20 01 00 00 00 00 20 fe ff ff ff 5a 20 04 00 00 00 58 fe 0e 02 00 fe 09 00 00 fe 0c 02 00 54 2a } //00 00 
	condition:
		any of ($a_*)
 
}
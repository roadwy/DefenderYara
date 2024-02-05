
rule TrojanDownloader_BAT_NetWire_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/NetWire.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 00 11 01 03 11 90 01 01 91 6f 90 01 03 0a 38 90 01 03 ff 11 90 01 01 2a 03 8e 69 13 90 01 01 38 90 01 03 ff 11 90 01 01 6f 90 01 03 0a 28 90 01 03 2b 13 03 90 00 } //01 00 
		$a_03_1 = {03 73 09 00 90 01 01 0a 28 90 01 03 0a 28 90 01 03 06 6f 90 01 03 0a 73 90 01 03 0a 20 90 01 03 03 6f 90 01 03 0a 13 00 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
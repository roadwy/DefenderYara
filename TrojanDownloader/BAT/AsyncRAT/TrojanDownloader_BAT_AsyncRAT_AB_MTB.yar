
rule TrojanDownloader_BAT_AsyncRAT_AB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 16 1b 6f 90 01 02 00 0a 0b 07 07 6f 90 01 02 00 0a 1c da 1c 6f 90 01 02 00 0a 0b 08 1f 0a da 0c 2b 90 01 01 09 1f 1e 3c 90 00 } //01 00 
		$a_01_1 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 } //01 00  GetMethods
		$a_01_2 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //01 00  GetExportedTypes
		$a_01_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}
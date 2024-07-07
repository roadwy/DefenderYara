
rule TrojanDownloader_BAT_Mendokus_A{
	meta:
		description = "TrojanDownloader:BAT/Mendokus.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 72 f1 02 00 70 fe 0c 02 00 28 17 00 00 06 72 55 00 00 70 28 0b 00 00 06 0a 06 72 21 03 00 70 fe 0c 02 00 28 17 00 00 06 6f 23 00 00 0a 2a } //1
		$a_03_1 = {fe 0e 02 00 fe 0d 02 00 4a 0b 38 90 01 02 ff ff 02 02 72 90 01 01 00 00 70 fe 0c 03 00 28 17 00 00 06 28 09 00 00 06 72 90 01 01 00 00 70 fe 0c 03 00 28 17 00 00 06 28 1a 00 00 0a 28 08 00 00 06 39 90 01 02 00 00 20 90 01 01 00 00 00 fe 0e 02 00 fe 0d 02 00 4a 0b 38 90 01 02 ff ff 38 90 01 02 00 00 20 90 01 01 00 00 00 fe 0e 02 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
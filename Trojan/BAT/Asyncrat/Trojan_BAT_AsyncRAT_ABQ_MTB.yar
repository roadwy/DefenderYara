
rule Trojan_BAT_AsyncRAT_ABQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 2c 07 08 6f 19 90 01 02 0a 00 dc 2a 90 0a 55 00 00 28 3a 90 01 02 0a 7e 1c 90 01 02 04 6f 3b 90 01 02 0a 72 cd 90 01 02 70 28 3c 90 01 02 0a 28 3d 90 01 02 0a 6f 3e 90 01 02 0a 0a 06 6f 3f 90 01 02 0a 0b 73 40 90 01 02 0a 0c 00 07 08 6f 41 90 01 02 0a 00 08 6f 42 90 01 02 0a 80 1b 90 01 02 04 00 de 0b 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_4 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}
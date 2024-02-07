
rule Trojan_BAT_Nanocore_ABLR_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {0d 08 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 13 04 11 04 09 6f 90 01 01 00 00 0a de 0c 11 04 2c 07 11 04 6f 90 01 01 00 00 0a dc 09 6f 90 01 01 00 00 0a 13 05 de 25 09 2c 06 09 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {42 75 66 66 65 72 65 64 53 74 72 65 61 6d } //01 00  BufferedStream
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}
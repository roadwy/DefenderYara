
rule Trojan_BAT_Nanocore_AGO_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 09 16 20 00 10 00 00 6f d2 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f d3 00 00 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_3 = {59 00 55 00 47 00 35 00 34 00 47 00 35 00 45 00 41 00 } //00 00  YUG54G5EA
	condition:
		any of ($a_*)
 
}
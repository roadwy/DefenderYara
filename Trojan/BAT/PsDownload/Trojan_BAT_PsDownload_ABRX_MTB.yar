
rule Trojan_BAT_PsDownload_ABRX_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.ABRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 2d 2b 32 2b 33 72 90 01 01 00 00 70 7e 90 01 01 00 00 0a 2b 2e 2b 33 1d 2d 0d 26 dd 90 01 01 00 00 00 2b 2f 15 2c f6 2b dc 2b 2b 2b f0 28 90 01 01 00 00 06 2b cd 28 90 01 01 00 00 0a 2b cc 07 2b cb 6f 90 01 01 00 00 0a 2b c6 6f 90 01 01 00 00 0a 2b cb 28 90 01 01 00 00 0a 2b c6 0b 2b ce 0c 2b d2 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}
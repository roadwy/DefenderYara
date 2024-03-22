
rule Trojan_BAT_PsDownload_ENAA_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.ENAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {26 14 0b 73 90 01 01 00 00 0a 0c 28 90 01 01 00 00 06 0b dd 90 01 01 00 00 00 08 39 90 01 01 00 00 00 08 6f 90 01 01 00 00 0a dc 07 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 0d 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_RedLine_KAO_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 11 01 6f 90 01 01 00 00 0a 03 11 01 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 13 02 90 00 } //01 00 
		$a_01_1 = {41 65 73 4d 61 6e 61 67 65 64 } //00 00  AesManaged
	condition:
		any of ($a_*)
 
}
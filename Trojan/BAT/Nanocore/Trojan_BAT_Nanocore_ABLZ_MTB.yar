
rule Trojan_BAT_Nanocore_ABLZ_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 06 07 11 06 9a 1f 10 28 90 01 01 00 00 0a d2 9c 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dd 90 00 } //01 00 
		$a_01_1 = {54 00 72 00 79 00 61 00 41 00 67 00 61 00 69 00 6e 00 2e 00 43 00 68 00 75 00 6e 00 6b 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Nanocore_ABMA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 9a 1f 10 28 90 01 01 00 00 0a d2 9c 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 2d dd 90 00 } //01 00 
		$a_01_1 = {4e 00 53 00 43 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
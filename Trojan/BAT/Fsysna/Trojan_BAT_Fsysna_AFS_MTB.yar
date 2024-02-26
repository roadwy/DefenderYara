
rule Trojan_BAT_Fsysna_AFS_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 13 00 00 0a 0a 73 14 00 00 0a 0b 07 72 1f 00 00 70 6f 90 01 01 00 00 0a 0a de 0a 07 2c 06 07 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Fsysna_AFS_MTB_2{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 06 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 2b 1e 00 08 11 06 16 11 07 6f 22 00 00 0a 00 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 00 11 07 16 fe 02 13 09 11 09 2d d7 } //00 00 
	condition:
		any of ($a_*)
 
}
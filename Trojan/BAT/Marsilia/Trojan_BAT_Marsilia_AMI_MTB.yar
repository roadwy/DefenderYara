
rule Trojan_BAT_Marsilia_AMI_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 08 9a 16 9a 7e 90 01 01 00 00 04 20 90 01 01 bd 66 06 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 2d 11 06 08 9a 16 9a 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 2b 05 28 90 01 01 00 00 0a 06 08 9a 17 9a 28 90 01 01 00 00 06 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_RemcosRAT_SGRG_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SGRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 08 58 08 5d 13 09 07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 13 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
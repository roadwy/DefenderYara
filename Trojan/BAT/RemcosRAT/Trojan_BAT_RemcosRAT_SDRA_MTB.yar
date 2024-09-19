
rule Trojan_BAT_RemcosRAT_SDRA_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SDRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 13 10 11 06 06 91 11 10 61 13 11 06 18 58 17 59 11 0a 5d 13 12 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
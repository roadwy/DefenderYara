
rule Trojan_BAT_Strictor_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Strictor.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 06 07 06 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 11 08 61 13 09 06 11 06 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
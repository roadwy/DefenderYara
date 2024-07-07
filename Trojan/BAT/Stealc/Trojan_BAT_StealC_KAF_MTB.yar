
rule Trojan_BAT_StealC_KAF_MTB{
	meta:
		description = "Trojan:BAT/StealC.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 09 93 07 09 07 8e 69 5d 93 59 20 00 01 00 00 59 20 00 01 00 00 5d 13 04 11 04 16 fe 04 13 05 11 05 2c 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
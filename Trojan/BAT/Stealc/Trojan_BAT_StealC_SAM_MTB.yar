
rule Trojan_BAT_StealC_SAM_MTB{
	meta:
		description = "Trojan:BAT/StealC.SAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 2d 01 00 04 28 40 03 00 06 28 25 00 00 0a 0a 06 28 26 00 00 0a 0b 07 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
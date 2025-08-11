
rule Trojan_BAT_StealC_SF_MTB{
	meta:
		description = "Trojan:BAT/StealC.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 10 11 1f 11 09 91 13 28 11 1f 11 09 11 28 11 27 61 11 1c 19 58 61 11 32 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
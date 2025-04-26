
rule Trojan_BAT_MultiRAT_RDA_MTB{
	meta:
		description = "Trojan:BAT/MultiRAT.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 28 01 00 00 2b 28 02 00 00 2b 28 27 01 00 0a 6f 28 01 00 0a 28 03 00 00 2b 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
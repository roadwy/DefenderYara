
rule Trojan_BAT_Mercurial_RDA_MTB{
	meta:
		description = "Trojan:BAT/Mercurial.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 11 05 93 07 11 05 93 6f 24 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
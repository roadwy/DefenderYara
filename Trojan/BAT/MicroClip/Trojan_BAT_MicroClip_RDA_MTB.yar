
rule Trojan_BAT_MicroClip_RDA_MTB{
	meta:
		description = "Trojan:BAT/MicroClip.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 07 6f ef 00 00 0a 6f f0 00 00 0a 13 05 08 07 11 05 17 6f f1 00 00 0a 6f f2 00 00 0a 26 11 04 17 d6 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
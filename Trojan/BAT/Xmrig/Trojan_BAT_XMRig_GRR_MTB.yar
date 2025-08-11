
rule Trojan_BAT_XMRig_GRR_MTB{
	meta:
		description = "Trojan:BAT/XMRig.GRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 67 00 00 70 28 14 00 00 0a 13 00 38 00 00 00 00 72 c1 00 00 70 28 14 00 00 0a 13 01 38 1a 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
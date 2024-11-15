
rule Trojan_BAT_ZgRAT_KAO_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 1d 11 09 11 21 11 22 61 19 11 42 58 61 11 34 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
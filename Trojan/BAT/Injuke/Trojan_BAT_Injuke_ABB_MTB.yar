
rule Trojan_BAT_Injuke_ABB_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 8e 69 5d 91 02 11 02 91 61 d2 6f 90 01 03 0a 38 00 00 00 00 11 02 17 58 13 02 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
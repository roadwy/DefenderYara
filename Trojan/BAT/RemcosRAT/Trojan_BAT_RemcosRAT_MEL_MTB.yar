
rule Trojan_BAT_RemcosRAT_MEL_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.MEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 11 0a 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
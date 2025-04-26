
rule Trojan_BAT_Zusy_CCJR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 02 11 05 91 08 61 07 06 91 61 b4 9c 38 52 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
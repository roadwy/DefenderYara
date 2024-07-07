
rule Trojan_BAT_Redcap_PSNF_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f fc 6a 17 6f c9 00 00 0a 26 72 6f 46 00 70 28 c4 00 00 0a 07 6f ca 00 00 0a 13 07 08 11 07 16 11 07 8e 69 6f cb 00 00 0a 00 06 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
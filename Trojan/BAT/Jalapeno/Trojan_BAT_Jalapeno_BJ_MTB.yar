
rule Trojan_BAT_Jalapeno_BJ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 1d 11 06 1d 95 11 02 1d 95 61 9e 38 b7 00 00 00 11 06 1f 0d 11 06 1f 0d 95 11 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
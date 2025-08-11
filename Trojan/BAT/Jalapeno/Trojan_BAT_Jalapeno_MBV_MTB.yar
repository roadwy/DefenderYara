
rule Trojan_BAT_Jalapeno_MBV_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 2b 16 95 11 2a 20 32 09 00 00 95 58 e0 91 11 2a 20 29 0f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
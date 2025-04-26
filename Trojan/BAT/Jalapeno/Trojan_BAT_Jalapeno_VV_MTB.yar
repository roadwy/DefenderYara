
rule Trojan_BAT_Jalapeno_VV_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 33 00 00 0a 80 01 00 00 04 73 34 00 00 0a 80 02 00 00 04 73 35 00 00 0a 80 03 00 00 04 73 35 00 00 0a 80 04 00 00 04 7e 03 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
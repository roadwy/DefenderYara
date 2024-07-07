
rule Trojan_BAT_Dcstl_PTCL_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PTCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 73 39 00 00 0a 7e 02 00 00 04 6f 3a 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f 3b 00 00 0a 00 00 de 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}

rule Trojan_BAT_Dcstl_PTBU_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PTBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 14 01 00 70 28 90 01 01 00 00 0a 10 00 73 2a 00 00 0a 0b 02 28 90 01 01 00 00 0a 0c 16 0d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
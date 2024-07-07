
rule Trojan_BAT_Small_PTDW_MTB{
	meta:
		description = "Trojan:BAT/Small.PTDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {de 91 f9 97 47 77 5a 19 3b 90 c6 7b 37 6a 66 df c9 78 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
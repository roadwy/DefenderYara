
rule Trojan_BAT_Jalapeno_GM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 28 11 00 00 0a 20 00 f2 2b 00 } //1
		$a_01_1 = {80 01 00 00 04 73 36 00 00 0a 80 02 00 00 04 73 37 00 00 0a 80 03 00 00 04 73 37 00 00 0a 80 04 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
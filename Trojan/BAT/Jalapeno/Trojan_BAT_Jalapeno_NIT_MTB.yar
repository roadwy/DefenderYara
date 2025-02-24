
rule Trojan_BAT_Jalapeno_NIT_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 00 28 1e 00 00 0a 7d 04 00 00 04 12 00 15 7d 03 00 00 04 12 00 7b 04 00 00 04 0b 12 01 12 00 28 ?? 00 00 2b 12 00 7c 04 00 00 04 28 ?? 00 00 0a 2a } //2
		$a_03_1 = {20 00 0c 00 00 28 ?? 00 00 0a 7e 01 00 00 04 28 ?? 00 00 06 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 28 ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
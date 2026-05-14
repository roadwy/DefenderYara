
rule Trojan_BAT_DarkTortilla_VKL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.VKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0f 17 6f ?? 02 00 0a 17 13 3a 2b c0 00 11 0f 18 6f ?? 02 00 0a 00 00 11 0f 6f ?? 02 00 0a 13 10 2b 00 2b 00 17 13 3c 11 3c } //5
		$a_03_1 = {2b 00 06 7b d8 01 00 04 11 08 11 10 28 ?? 01 00 06 28 1e 00 00 2b 6f ?? 01 00 0a 00 de 45 2b 00 19 13 3e 11 3e } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}
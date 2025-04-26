
rule Trojan_BAT_Strictor_ARS_MTB{
	meta:
		description = "Trojan:BAT/Strictor.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 19 2f 02 2b 54 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0a 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 06 1e 63 } //2
		$a_03_1 = {02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? 00 00 0a 59 0b 03 06 07 28 ?? 00 00 06 00 2a } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
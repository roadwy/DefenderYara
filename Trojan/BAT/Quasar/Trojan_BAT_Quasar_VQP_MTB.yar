
rule Trojan_BAT_Quasar_VQP_MTB{
	meta:
		description = "Trojan:BAT/Quasar.VQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0f 18 6f ?? 02 00 0a 00 00 11 0f 6f ?? 02 00 0a 13 10 2b 00 2b 00 16 13 3d 11 3d } //4
		$a_03_1 = {2b 00 06 7b d8 01 00 04 11 08 11 10 28 ?? 01 00 06 28 ?? 00 00 2b 6f ?? 01 00 0a 00 de 45 2b 00 1a 13 3f 11 3f } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}
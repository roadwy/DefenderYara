
rule Trojan_BAT_DllInject_MBDZ_MTB{
	meta:
		description = "Trojan:BAT/DllInject.MBDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {54 11 05 17 06 1e 58 4a 17 59 6f ?? 00 00 0a 25 1f 7a 6f ?? 00 00 0a 16 fe 04 16 fe 01 13 06 1f 74 6f 59 00 00 0a 16 fe 04 16 fe 01 13 07 11 05 06 1e 58 4a 17 58 } //1
		$a_01_1 = {4c 64 61 61 64 70 64 6c 6b 71 6f } //1 Ldaadpdlkqo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
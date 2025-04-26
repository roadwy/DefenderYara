
rule Trojan_BAT_Lazy_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 27 0d 11 04 13 06 12 06 03 28 ?? 00 00 06 11 06 74 ?? 00 00 01 13 04 1f 28 0d 11 04 6f ?? 00 00 0a 13 05 1f 29 0d 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0a } //4
		$a_80_1 = {44 62 61 74 69 63 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //Dbatic.Resources.resources  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}

rule Trojan_BAT_Small_CXRM_MTB{
	meta:
		description = "Trojan:BAT/Small.CXRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 12 00 00 06 0a 28 20 00 00 0a 06 6f 21 00 00 0a 28 11 00 00 06 75 02 00 00 1b 0b 07 16 07 8e 69 28 ?? 00 00 0a 07 2a } //1
		$a_01_1 = {4f 00 77 00 74 00 77 00 68 00 7a 00 64 00 6c 00 69 00 66 00 } //1 Owtwhzdlif
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
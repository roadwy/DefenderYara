
rule Trojan_BAT_Jalapeno_PMOH_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.PMOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? 00 00 0a 59 0b 03 06 07 28 ?? 00 00 06 00 2a } //9
		$a_01_1 = {4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 } //1
	condition:
		((#a_03_0  & 1)*9+(#a_01_1  & 1)*1) >=10
 
}
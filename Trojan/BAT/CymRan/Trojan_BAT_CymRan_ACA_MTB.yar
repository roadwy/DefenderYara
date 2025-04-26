
rule Trojan_BAT_CymRan_ACA_MTB{
	meta:
		description = "Trojan:BAT/CymRan.ACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 16 16 6f ?? 00 00 0a 0a 06 2c 05 00 16 0b de 0b 00 17 0b de 06 26 00 17 0b de 00 } //1
		$a_03_1 = {0a 16 fe 01 0c 08 2c 61 00 02 28 ?? 00 00 0a 0d 09 2c 51 00 00 02 73 ?? 00 00 0a 03 04 05 28 ?? 00 00 0a 25 0a 13 04 00 06 16 6a 16 6a 6f ?? 00 00 0a 00 00 06 16 6a 16 6a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
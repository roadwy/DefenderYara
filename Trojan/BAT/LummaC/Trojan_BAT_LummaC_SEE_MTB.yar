
rule Trojan_BAT_LummaC_SEE_MTB{
	meta:
		description = "Trojan:BAT/LummaC.SEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 08 1e 6f 29 00 00 0a 17 8d 2c 00 00 01 6f 2a 00 00 0a 28 0e 00 00 06 28 1b 00 00 0a 72 ?? ?? ?? 70 28 2b 00 00 0a 6f 2c 00 00 0a } //1
		$a_00_1 = {11 00 28 24 00 00 0a 13 01 38 f4 01 00 00 fe 0c 06 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
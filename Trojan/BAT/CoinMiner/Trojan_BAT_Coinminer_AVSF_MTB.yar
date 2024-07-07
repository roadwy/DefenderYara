
rule Trojan_BAT_Coinminer_AVSF_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.AVSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 08 18 58 0c 08 06 32 e4 07 2a 90 00 } //1
		$a_01_1 = {64 00 6f 00 62 00 65 00 72 00 6d 00 61 00 6e 00 } //1 doberman
		$a_01_2 = {61 00 38 00 64 00 6f 00 53 00 75 00 44 00 69 00 74 00 4f 00 7a 00 31 00 68 00 5a 00 65 00 23 00 } //1 a8doSuDitOz1hZe#
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_BAT_XenoRAT_MBYF_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.MBYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 03 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a } //1
		$a_01_1 = {65 6d 6f 76 65 00 6d 61 6e 61 67 69 6e 67 5f 61 70 70 2e 65 78 65 00 63 62 53 69 7a 65 00 46 69 6e 61 6c } //1
		$a_01_2 = {54 00 61 00 73 00 6b 00 20 00 54 00 6f 00 20 00 52 00 75 00 6e 00 00 07 22 00 2c 00 22 00 00 1b 2f 00 64 00 65 00 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_BAT_Phorpiex_MTB{
	meta:
		description = "Trojan:BAT/Phorpiex!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {16 0a 2b 0e 02 06 02 06 91 1f 1d 61 d2 9c 06 17 58 0a 06 02 8e 69 32 ec 02 2a } //1
		$a_01_1 = {59 00 50 00 45 00 62 00 63 00 68 00 4f 00 50 00 5a 00 58 00 73 00 78 00 36 00 51 00 74 00 57 00 4b 00 75 00 49 00 5a 00 76 00 49 00 52 00 57 00 74 00 47 00 50 00 55 00 34 00 } //1 YPEbchOPZXsx6QtWKuIZvIRWtGPU4
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
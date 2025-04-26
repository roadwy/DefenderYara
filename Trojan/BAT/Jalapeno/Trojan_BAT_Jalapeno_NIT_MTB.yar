
rule Trojan_BAT_Jalapeno_NIT_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 00 28 1e 00 00 0a 7d 04 00 00 04 12 00 15 7d 03 00 00 04 12 00 7b 04 00 00 04 0b 12 01 12 00 28 ?? 00 00 2b 12 00 7c 04 00 00 04 28 ?? 00 00 0a 2a } //2
		$a_03_1 = {20 00 0c 00 00 28 ?? 00 00 0a 7e 01 00 00 04 28 ?? 00 00 06 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 28 ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Jalapeno_NIT_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 27 00 00 0a 20 e8 03 00 00 20 88 13 00 00 6f 28 00 00 0a 28 21 00 00 0a 7e 0f 00 00 04 2d 0a 28 1e 00 00 06 28 18 00 00 06 7e 16 00 00 04 6f 29 00 00 0a 26 17 2d c8 } //2
		$a_01_1 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //1 capCreateCaptureWindowA
		$a_01_2 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //1 capGetDriverDescriptionA
		$a_01_3 = {41 6e 74 69 76 69 72 75 73 } //1 Antivirus
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
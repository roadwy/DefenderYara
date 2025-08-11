
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
rule Trojan_BAT_Jalapeno_NIT_MTB_3{
	meta:
		description = "Trojan:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 03 08 03 6f 07 00 00 0a 5d 17 d6 17 28 ?? 00 00 0a 28 ?? 00 00 0a da 13 04 06 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 05 11 05 2d b5 } //2
		$a_03_1 = {a2 00 11 0a 28 ?? 00 00 0a 07 28 ?? 00 00 06 28 ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Jalapeno_NIT_MTB_4{
	meta:
		description = "Trojan:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 28 df 03 00 0a 00 28 ?? 03 00 06 80 4f 00 00 0a 28 ?? 05 00 06 6f 00 06 00 06 80 1a 03 00 0a 28 ?? 05 00 06 6f 02 06 00 06 72 77 03 00 70 28 ?? 00 00 0a 16 fe 01 0b 07 2d 1b 00 28 ?? 05 00 06 6f 02 06 00 06 72 17 22 00 70 28 ?? 01 00 0a 80 10 02 00 0a 00 16 28 ?? 03 00 0a 00 73 df 00 00 06 0a 06 6f e2 00 00 0a 17 fe 01 16 fe 01 0b 07 2d 0b 73 89 02 00 06 28 ?? 03 00 0a 00 2a } //2
		$a_01_1 = {44 65 63 72 79 70 74 53 74 72 69 6e 67 } //1 DecryptString
		$a_01_2 = {44 65 63 72 79 70 74 44 45 53 } //1 DecryptDES
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Jalapeno_NIT_MTB_5{
	meta:
		description = "Trojan:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {12 00 12 01 28 02 00 00 06 07 28 01 00 00 0a 0c 7e 05 00 00 04 0d 08 7e 06 00 00 04 6f 02 00 00 0a 13 04 11 04 14 28 03 00 00 0a 39 01 00 00 00 2a 11 04 09 6f 04 00 00 0a 13 05 11 05 14 28 05 00 00 0a 39 01 00 00 00 2a 11 05 14 18 8d 04 00 00 01 13 06 11 06 16 28 06 00 00 0a a2 11 06 17 06 28 04 00 00 06 a2 11 06 6f 07 00 00 0a 26 2a } //2
		$a_01_1 = {1e 8d 0a 00 00 01 0c 07 28 0a 00 00 0a 03 6f 0b 00 00 0a 6f 0c 00 00 0a 0d 09 16 08 16 1e 28 0d 00 00 0a 06 08 6f 0e 00 00 0a 06 18 6f 0f 00 00 0a 06 18 6f 10 00 00 0a 06 6f 11 00 00 0a 13 04 02 28 12 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f 13 00 00 0a 13 06 28 0a 00 00 0a 11 06 6f 14 00 00 0a 13 07 dd 0d 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
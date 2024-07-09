
rule Trojan_BAT_Fsysna_AAHD_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AAHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 1d 0b 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 02 28 ?? 00 00 06 0c 2b 00 08 2a } //3
		$a_01_1 = {38 00 2b 00 69 00 6c 00 6c 00 56 00 4c 00 75 00 31 00 63 00 69 00 39 00 5a 00 41 00 61 00 55 00 77 00 4f 00 6f 00 56 00 46 00 5a 00 72 00 2f 00 5a 00 68 00 67 00 30 00 44 00 39 00 42 00 55 00 38 00 74 00 75 00 45 00 47 00 47 00 79 00 30 00 4a 00 4c 00 59 00 3d 00 } //1 8+illVLu1ci9ZAaUwOoVFZr/Zhg0D9BU8tuEGGy0JLY=
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
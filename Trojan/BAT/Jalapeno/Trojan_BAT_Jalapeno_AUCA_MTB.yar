
rule Trojan_BAT_Jalapeno_AUCA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AUCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 77 65 20 75 6e 64 65 72 73 74 61 6e 64 20 75 6e 64 65 72 73 74 61 6e 64 20 67 61 6c 61 78 79 20 73 75 70 70 6f 72 74 20 6c 61 72 67 65 20 63 6f 6d 6d 75 6e 69 63 61 74 65 20 6e 65 74 77 6f 72 6b 20 74 65 61 63 68 20 67 72 6f 77 } //2 Lwe understand understand galaxy support large communicate network teach grow
		$a_01_1 = {71 75 69 63 6b 20 76 69 73 69 6f 6e 20 73 6c 6f 77 20 77 68 69 74 65 20 6f 72 67 61 6e 69 7a 65 } //2 quick vision slow white organize
		$a_01_2 = {6c 65 61 64 20 69 6e 73 70 69 72 65 20 63 68 61 6e 67 65 } //2 lead inspire change
		$a_01_3 = {64 69 72 65 63 74 20 73 6d 61 6c 6c 20 64 69 72 65 63 74 } //2 direct small direct
		$a_01_4 = {75 73 20 63 6f 6c 6c 61 62 6f 72 61 74 65 20 63 6f 6e 6e 65 63 74 } //1 us collaborate connect
		$a_01_5 = {73 75 70 70 6f 72 74 20 67 72 65 65 6e 20 79 6f 75 } //1 support green you
		$a_01_6 = {24 35 34 38 61 63 64 62 63 2d 66 63 65 32 2d 34 64 38 33 2d 61 61 30 35 2d 37 62 36 31 63 61 37 35 62 39 62 65 } //1 $548acdbc-fce2-4d83-aa05-7b61ca75b9be
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}
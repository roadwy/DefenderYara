
rule Trojan_BAT_LummaC_AVCA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AVCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 69 63 65 20 63 6f 6d 6d 75 6e 69 63 61 74 65 20 74 68 65 6d 20 70 72 6f 64 75 63 65 20 70 6c 61 6e 65 74 20 64 69 72 65 63 74 20 70 6c 61 6e 65 74 20 72 6f 75 67 68 20 6c 65 61 72 6e 20 62 75 69 6c 64 } //3 service communicate them produce planet direct planet rough learn build
		$a_01_1 = {24 36 33 30 30 35 30 35 65 2d 64 64 64 35 2d 34 62 66 30 2d 39 32 34 35 2d 35 39 36 64 30 30 36 37 66 34 35 33 } //2 $6300505e-ddd5-4bf0-9245-596d0067f453
		$a_01_2 = {73 75 70 70 6f 72 74 20 77 65 20 63 6f 6e 6e 65 63 74 } //2 support we connect
		$a_01_3 = {77 65 20 6e 65 77 20 79 6f 75 20 70 72 6f 6a 65 63 74 20 6e 65 77 } //1 we new you project new
		$a_01_4 = {6f 62 6a 65 63 74 20 6f 72 67 61 6e 69 7a 65 20 79 65 6c 6c 6f 77 } //1 object organize yellow
		$a_01_5 = {63 6f 6c 6c 61 62 6f 72 61 74 65 20 63 6f 73 6d 6f 73 20 79 6f 75 } //1 collaborate cosmos you
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=11
 
}
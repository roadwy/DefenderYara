
rule Trojan_BAT_Bobik_GMD_MTB{
	meta:
		description = "Trojan:BAT/Bobik.GMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {68 63 69 6a 6b 63 6c } //hcijkcl  1
		$a_80_1 = {6d 63 6e 63 6f 63 71 6a 73 6a 75 6a 78 77 7a } //mcncocqjsjujxwz  1
		$a_80_2 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 35 30 38 33 37 36 30 32 37 39 3a 41 41 48 44 66 72 48 76 65 42 37 32 66 69 73 72 36 62 4d 7a 34 4a 51 5a 6a 6d 73 70 51 49 67 7a 79 58 59 2f } //api.telegram.org/bot5083760279:AAHDfrHveB72fisr6bMz4JQZjmspQIgzyXY/  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}

rule Trojan_BAT_Redline_GLY_MTB{
	meta:
		description = "Trojan:BAT/Redline.GLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 3a 9d 6f 90 01 03 0a 0c 08 16 9a 28 90 01 03 06 0d 06 09 6f 90 01 03 0a 00 08 17 9a 28 90 01 03 06 0b 28 90 01 03 0a 06 6f 90 01 03 0a 07 16 07 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 13 04 11 04 13 05 de 10 90 00 } //10
		$a_80_1 = {59 46 70 6f 47 51 40 24 56 72 55 4d 66 36 34 74 5a 39 65 67 5e 52 69 61 51 53 5a 5e 50 77 25 2a } //YFpoGQ@$VrUMf64tZ9eg^RiaQSZ^Pw%*  1
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_80_3 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 35 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 5 & Del  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}
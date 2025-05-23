
rule Ransom_Win32_Tescrypt_O{
	meta:
		description = "Ransom:Win32/Tescrypt.O,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {52 ff d7 83 c4 08 85 c0 75 3f 8d 85 fc df ff ff 68 ?? ?? ?? ?? 50 ff d7 83 c4 08 85 c0 75 2a } //2
		$a_01_1 = {5c 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 } //1 \recover_file_
		$a_01_2 = {25 00 73 00 5c 00 5f 00 52 00 65 00 43 00 6f 00 56 00 65 00 52 00 79 00 5f 00 2e 00 54 00 58 00 54 00 } //1 %s\_ReCoVeRy_.TXT
		$a_01_3 = {25 00 73 00 5c 00 5f 00 52 00 65 00 43 00 6f 00 56 00 65 00 52 00 79 00 5f 00 25 00 73 00 } //1 %s\_ReCoVeRy_%s
		$a_01_4 = {25 00 73 00 5c 00 5f 00 52 00 65 00 43 00 6f 00 56 00 65 00 52 00 79 00 5f 00 2e 00 70 00 6e 00 67 00 } //1 %s\_ReCoVeRy_.png
		$a_01_5 = {30 00 39 00 38 00 37 00 73 00 6b 00 66 00 67 00 39 00 39 00 38 00 6a 00 6b 00 68 00 38 00 39 00 33 00 34 00 35 00 6a 00 6b 00 39 00 38 00 37 00 34 00 33 00 37 00 6b 00 } //1 0987skfg998jkh89345jk987437k
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}

rule Trojan_Win32_VBKrypt_DS_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {18 43 00 31 18 43 00 45 18 43 00 68 18 43 00 18 19 43 00 1d 19 43 00 1d 19 43 00 3c 19 43 00 4b 19 43 00 d1 19 43 00 73 } //2
		$a_01_1 = {b8 9c 54 b9 32 9f e7 85 02 9a 94 35 f9 47 95 89 7b 04 83 e2 31 ef 2a 4f ad 33 99 66 cf 11 b7 } //2
		$a_01_2 = {00 ac 10 34 47 67 3e 32 41 2b 1a 75 bb 2a f1 40 93 81 a1 19 15 6a 00 00 00 4c a4 99 17 89 dc ec bc 3b bd 2d 33 e2 } //2
		$a_01_3 = {0d 14 00 00 1e 00 27 2e 35 3c 44 4b 52 59 60 68 6f 00 78 7f 86 8e 95 9c 00 a4 ac } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}
rule Trojan_Win32_VBKrypt_DS_MTB_2{
	meta:
		description = "Trojan:Win32/VBKrypt.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 00 6f 00 72 00 69 00 63 00 6f 00 72 00 20 00 74 00 62 00 72 00 } //1 foricor tbr
		$a_01_1 = {79 00 61 00 76 00 61 00 65 00 20 00 72 00 6a 00 74 00 6a 00 65 00 72 00 } //1 yavae rjtjer
		$a_01_2 = {73 00 61 00 6c 00 41 00 76 00 69 00 6e 00 6f 00 20 00 76 00 69 00 6c 00 69 00 64 00 69 00 6c 00 72 00 } //1 salAvino vilidilr
		$a_01_3 = {72 00 69 00 6c 00 41 00 76 00 69 00 6e 00 6f 00 20 00 64 00 61 00 6c 00 69 00 76 00 69 00 6c 00 72 00 } //1 rilAvino dalivilr
		$a_01_4 = {6c 00 65 00 73 00 65 00 64 00 69 00 76 00 6f 00 73 00 69 00 63 00 20 00 64 00 69 00 63 00 72 00 } //1 lesedivosic dicr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}

rule Trojan_BAT_AsyncRAT_MBJM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 0f 02 11 0f 91 11 0d 61 11 09 11 07 91 61 b4 9c 11 07 03 6f ?? 00 00 0a 17 da 33 05 } //1
		$a_01_1 = {76 00 69 00 56 00 76 00 53 00 66 00 74 00 62 00 73 00 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AsyncRAT_MBJM_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2b db 17 2c 53 1f 32 28 } //1
		$a_01_1 = {dd 00 d5 00 4f 00 cf 00 57 00 41 00 83 00 e8 00 ec 00 d6 } //1
		$a_01_2 = {44 32 58 38 37 48 34 79 62 75 50 54 35 61 34 50 34 39 73 4c 30 69 } //1 D2X87H4ybuPT5a4P49sL0i
		$a_01_3 = {24 30 35 61 30 35 30 31 32 2d 33 33 63 31 2d 34 33 31 38 2d 39 31 34 30 2d 64 66 34 36 64 64 64 63 33 62 61 64 } //1 $05a05012-33c1-4318-9140-df46dddc3bad
		$a_01_4 = {53 65 72 76 69 63 65 73 2e 65 78 65 } //1 Services.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
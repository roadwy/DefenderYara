
rule Trojan_BAT_Bitminer_GP_MTB{
	meta:
		description = "Trojan:BAT/Bitminer.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 6c 00 75 00 73 00 2d 00 63 00 63 00 6d 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 70 00 72 00 6f 00 67 00 2e 00 72 00 75 00 2f 00 6e 00 76 00 72 00 74 00 63 00 36 00 34 00 5f 00 31 00 31 00 32 00 5f 00 30 00 2e 00 64 00 6c 00 6c 00 } //1 https://plus-ccmcleanerprog.ru/nvrtc64_112_0.dll
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 6c 00 75 00 73 00 2d 00 63 00 63 00 6d 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 70 00 72 00 6f 00 67 00 2e 00 72 00 75 00 2f 00 6e 00 76 00 72 00 74 00 63 00 2d 00 62 00 75 00 69 00 6c 00 74 00 69 00 6e 00 73 00 36 00 34 00 5f 00 31 00 31 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 https://plus-ccmcleanerprog.ru/nvrtc-builtins64_112.dll
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 6c 00 75 00 73 00 2d 00 63 00 63 00 6d 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 70 00 72 00 6f 00 67 00 2e 00 72 00 75 00 2f 00 64 00 64 00 62 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 } //1 https://plus-ccmcleanerprog.ru/ddb64.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
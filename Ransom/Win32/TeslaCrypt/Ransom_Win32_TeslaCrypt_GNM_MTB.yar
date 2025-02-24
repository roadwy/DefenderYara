
rule Ransom_Win32_TeslaCrypt_GNM_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 c2 31 f1 09 d1 89 0c 24 0f 85 } //10
		$a_80_1 = {4a 6f 79 68 76 2e 70 65 77 } //Joyhv.pew  1
		$a_01_2 = {6c 00 6f 00 68 00 75 00 67 00 76 00 62 00 } //1 lohugvb
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
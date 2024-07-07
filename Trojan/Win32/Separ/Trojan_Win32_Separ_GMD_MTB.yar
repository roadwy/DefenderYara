
rule Trojan_Win32_Separ_GMD_MTB{
	meta:
		description = "Trojan:Win32/Separ.GMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {40 6a 68 64 66 6b 6c 64 66 68 6e 64 66 6b 6a 64 66 6e 62 66 6b 6c 66 6e 66 40 4e 65 74 73 65 61 6c 49 73 54 68 65 42 65 73 74 4c 69 } //1 @jhdfkldfhndfkjdfnbfklfnf@NetsealIsTheBestLi
		$a_01_1 = {69 76 63 79 64 70 76 73 6f 56 71 79 4d 42 33 45 6b 31 4f 72 78 4f 41 66 5a 47 46 33 64 67 4a 38 } //1 ivcydpvsoVqyMB3Ek1OrxOAfZGF3dgJ8
		$a_01_2 = {61 30 48 57 44 53 4b 58 36 73 70 36 37 69 43 36 } //1 a0HWDSKX6sp67iC6
		$a_80_3 = {53 63 69 54 45 2e 45 58 45 } //SciTE.EXE  1
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
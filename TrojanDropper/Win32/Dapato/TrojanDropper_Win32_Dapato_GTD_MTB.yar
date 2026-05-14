
rule TrojanDropper_Win32_Dapato_GTD_MTB{
	meta:
		description = "TrojanDropper:Win32/Dapato.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 6f 77 65 22 22 72 22 22 73 22 22 68 22 22 65 6c 6c 2e 65 78 65 20 2d 45 78 22 22 65 63 22 22 75 74 69 22 22 6f 22 22 6e 50 6f 6c 22 22 69 63 22 22 79 20 42 79 22 22 70 61 22 22 73 22 22 73 20 2d 43 22 22 6f 6d 22 22 6d 61 22 22 6e 22 22 64 } //cmd.exe /C powe""r""s""h""ell.exe -Ex""ec""uti""o""nPol""ic""y By""pa""s""s -C""om""ma""n""d  5
		$a_80_1 = {41 64 22 22 64 22 22 2d 4d 22 22 70 50 72 22 22 65 66 22 22 65 72 65 22 22 6e 63 65 20 2d 45 78 22 22 63 6c 22 22 75 73 69 6f 6e 22 22 50 61 74 68 } //Ad""d""-M""pPr""ef""ere""nce -Ex""cl""usion""Path  1
		$a_80_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 20 20 22 73 74 61 72 74 20 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //cmd.exe /C   "start  rundll32.exe  1
		$a_01_3 = {69 6f 53 70 65 63 69 61 6c 2e 69 6e 69 } //1 ioSpecial.ini
		$a_80_4 = {5c 74 65 6c 65 67 72 6f 6d 2e 65 78 65 } //\telegrom.exe  1
		$a_80_5 = {5c 74 65 6c 65 67 72 6f 6d 2e 6c 6e 6b } //\telegrom.lnk  1
		$a_80_6 = {5c 41 75 74 6f 2e 64 61 74 } //\Auto.dat  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=11
 
}
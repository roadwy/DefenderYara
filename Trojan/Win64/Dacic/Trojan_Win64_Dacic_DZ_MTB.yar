
rule Trojan_Win64_Dacic_DZ_MTB{
	meta:
		description = "Trojan:Win64/Dacic.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 65 72 74 75 74 69 6c 20 2d 68 61 73 68 66 69 6c 65 } //2 certutil -hashfile
		$a_81_1 = {26 26 20 74 69 6d 65 6f 75 74 20 2f 74 20 35 } //2 && timeout /t 5
		$a_81_2 = {73 74 61 72 74 20 63 6d 64 20 2f 43 20 22 63 6f 6c 6f 72 20 62 20 26 26 20 74 69 74 6c 65 20 45 72 72 6f 72 20 26 26 20 65 63 68 6f } //2 start cmd /C "color b && title Error && echo
		$a_81_3 = {5b 20 2d 20 5d 20 4c 4f 41 44 49 4e 47 20 48 57 49 44 20 3a 20 57 41 4e 4e 41 43 52 59 } //1 [ - ] LOADING HWID : WANNACRY
		$a_81_4 = {57 41 4e 4e 41 43 52 59 2e 65 78 65 } //1 WANNACRY.exe
		$a_81_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4b 73 44 75 6d 70 65 72 2e 65 78 65 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /f /im KsDumper.exe >nul 2>&1
		$a_81_6 = {5c 5c 2e 5c 6b 70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //1 \\.\kprocesshacker
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}

rule Trojan_Win32_BitRAT_NB_MTB{
	meta:
		description = "Trojan:Win32/BitRAT.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 69 74 73 2e 70 73 31 } //1 bits.ps1
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 78 65 63 2e 62 61 74 } //1 cmd.exe /c exec.bat
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 49 6e 73 74 61 6c 6c 48 69 6e 66 53 65 63 74 69 6f 6e } //1 rundll32.exe %s,InstallHinfSection
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 61 64 76 70 61 63 6b 2e 64 6c 6c 2c 44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //1 rundll32.exe %sadvpack.dll,DelNodeRunDLL32
		$a_01_4 = {50 4d 53 43 46 } //1 PMSCF
		$a_01_5 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //1 DecryptFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule Trojan_BAT_Quasar_GIF_MTB{
	meta:
		description = "Trojan:BAT/Quasar.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_1 = {61 30 37 34 39 39 38 36 2e 78 73 70 68 2e 72 75 } //a0749986.xsph.ru  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d } //Software\Policies\Microsoft\Windows\System  1
		$a_80_3 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 64 65 66 33 2e 65 78 65 } //\ProgramData\def3.exe  1
		$a_80_4 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 6b 72 6f 73 41 43 2e 65 78 65 } //\ProgramData\AkrosAC.exe  1
		$a_01_5 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
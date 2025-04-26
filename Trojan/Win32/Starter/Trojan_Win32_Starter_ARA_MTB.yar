
rule Trojan_Win32_Starter_ARA_MTB{
	meta:
		description = "Trojan:Win32/Starter.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 61 73 70 68 6f 6e 65 2e 70 64 62 } //2 rasphone.pdb
		$a_01_1 = {63 72 61 73 68 72 65 70 6f 72 74 65 72 2e 70 64 62 } //2 crashreporter.pdb
		$a_80_2 = {53 75 62 6d 69 74 43 72 61 73 68 52 65 70 6f 72 74 } //SubmitCrashReport  2
		$a_80_3 = {5c 2a 2e 64 6d 70 } //\*.dmp  2
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 63 72 61 73 68 72 65 70 6f 72 74 65 72 2e 65 78 65 } //Software\Classes\Applications\crashreporter.exe  2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}
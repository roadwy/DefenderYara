
rule Trojan_Win32_Strictor_GMR_MTB{
	meta:
		description = "Trojan:Win32/Strictor.GMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 76 6d 70 30 } //1 .vmp0
		$a_01_1 = {50 46 47 79 64 63 42 } //1 PFGydcB
		$a_80_2 = {4c 6f 67 6f 6e 2e 65 78 65 } //Logon.exe  1
		$a_01_3 = {72 78 6a 68 64 6c 71 2e 62 61 6b } //1 rxjhdlq.bak
		$a_01_4 = {58 57 75 69 71 78 } //1 XWuiqx
		$a_01_5 = {69 77 76 52 4d 48 78 } //1 iwvRMHx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
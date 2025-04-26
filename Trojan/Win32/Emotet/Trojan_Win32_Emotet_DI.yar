
rule Trojan_Win32_Emotet_DI{
	meta:
		description = "Trojan:Win32/Emotet.DI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 00 6f 00 32 00 2a 00 57 00 36 00 79 00 40 00 64 00 2f 00 6d 00 3c 00 23 00 } //1 xo2*W6y@d/m<#
		$a_01_1 = {47 43 57 59 71 31 67 2e 70 64 62 } //1 GCWYq1g.pdb
		$a_01_2 = {3d 20 3d 24 3d 28 3d 2c 3d 30 3d 34 3d 38 3d 3c 3d 40 3d 44 3d 48 3d 4c 3d 50 3d 54 3d 58 3d 5c 3d } //1 = =$=(=,=0=4=8=<=@=D=H=L=P=T=X=\=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_DI_2{
	meta:
		description = "Trojan:Win32/Emotet.DI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 73 65 78 79 54 72 61 63 6b 69 6e 67 6a 6f 72 64 61 6e 32 33 } //1 bsexyTrackingjordan23
		$a_01_1 = {2f 64 51 57 50 49 43 6c 5f 48 75 64 65 31 76 2e 70 64 62 } //1 /dQWPICl_Hude1v.pdb
		$a_01_2 = {67 00 70 00 65 00 61 00 6d 00 2b 00 46 00 2f 00 66 00 62 00 58 00 } //1 gpeam+F/fbX
		$a_01_3 = {73 5a 6c 61 75 6e 63 68 65 64 66 75 63 6b 6f 66 66 6a 7a 47 4d 41 77 68 69 63 68 } //1 sZlaunchedfuckoffjzGMAwhich
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_DI_3{
	meta:
		description = "Trojan:Win32/Emotet.DI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 00 63 00 31 00 33 00 31 00 33 00 74 00 6b 00 78 00 61 00 64 00 73 00 } //1 2c1313tkxads
		$a_01_1 = {77 4a 52 45 6a 65 40 23 24 59 4a 45 72 68 71 45 57 52 4a 61 6a 33 34 2e 70 64 62 } //1 wJREje@#$YJErhqEWRJaj34.pdb
		$a_01_2 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 41 00 68 00 65 00 61 00 64 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 41 00 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
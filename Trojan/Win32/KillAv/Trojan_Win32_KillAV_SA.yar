
rule Trojan_Win32_KillAV_SA{
	meta:
		description = "Trojan:Win32/KillAV.SA,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 72 65 6c 65 61 73 65 5c 6b 69 6c 6c 61 76 2e 70 64 62 } //\release\killav.pdb  10
		$a_80_1 = {6d 73 6d 70 65 6e 67 2e 65 78 65 } //msmpeng.exe  1
		$a_80_2 = {73 65 6e 74 69 6e 65 6c 61 67 65 6e 74 2e 65 78 65 } //sentinelagent.exe  1
		$a_80_3 = {61 6c 73 76 63 2e 65 78 65 } //alsvc.exe  1
		$a_80_4 = {6d 63 74 72 61 79 2e 65 78 65 } //mctray.exe  1
		$a_80_5 = {73 61 76 73 65 72 76 69 63 65 2e 65 78 65 } //savservice.exe  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=12
 
}
rule Trojan_Win32_KillAV_SA_2{
	meta:
		description = "Trojan:Win32/KillAV.SA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {2f 63 20 64 65 6c } ///c del  1
		$a_80_1 = {5c 5c 2e 5c 61 73 77 73 70 5f 61 72 70 6f 74 32 } //\\.\aswsp_arpot2  1
		$a_80_2 = {5c 5c 2e 5c 61 73 77 73 70 5f 61 76 61 72 } //\\.\aswsp_avar  1
		$a_80_3 = {64 65 76 69 63 65 69 6f 63 6f 6e 74 72 6f 6c } //deviceiocontrol  1
		$a_80_4 = {63 72 65 61 74 65 74 6f 6f 6c 68 65 6c 70 33 32 73 6e 61 70 73 68 6f 74 } //createtoolhelp32snapshot  1
		$a_80_5 = {70 72 6f 63 65 73 73 33 32 66 69 72 73 74 77 } //process32firstw  1
		$a_80_6 = {70 72 6f 63 65 73 73 33 32 6e 65 78 74 77 } //process32nextw  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}

rule Trojan_Win32_AntiVm_EM_MTB{
	meta:
		description = "Trojan:Win32/AntiVm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 00 4d 00 77 00 61 00 72 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //1 VMwareService.exe
		$a_01_1 = {56 00 4d 00 77 00 61 00 72 00 65 00 54 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00 } //1 VMwareTray.exe
		$a_01_2 = {42 00 69 00 74 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 } //1 BitDefender
		$a_01_3 = {6d 00 73 00 73 00 65 00 63 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 mssecess.exe
		$a_01_4 = {51 00 75 00 69 00 63 00 6b 00 48 00 65 00 61 00 6c 00 } //1 QuickHeal
		$a_01_5 = {63 61 6e 67 6b 75 5c 57 69 6e 4f 73 43 6c 69 65 6e 74 50 72 6f 6a 65 63 74 } //1 cangku\WinOsClientProject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
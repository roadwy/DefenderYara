
rule Trojan_Win64_ReconLoader_CM_MTB{
	meta:
		description = "Trojan:Win64/ReconLoader.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {69 73 5f 76 6d 3d 25 64 26 61 76 5f 73 6f 66 74 77 61 72 65 3d 25 73 } //2 is_vm=%d&av_software=%s
		$a_01_1 = {2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 25 73 25 73 27 22 } //2 /c powershell.exe -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath '%s%s'"
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {65 78 66 69 6c 5f 64 61 74 61 3d 25 73 } //2 exfil_data=%s
		$a_01_4 = {56 4d 77 61 72 65 } //2 VMware
		$a_01_5 = {56 69 72 74 75 61 6c 42 6f 78 } //2 VirtualBox
		$a_01_6 = {73 65 63 75 72 69 74 79 63 65 6e 74 65 72 32 20 70 61 74 68 20 61 6e 74 69 76 69 72 75 73 70 72 6f 64 75 63 74 } //2 securitycenter2 path antivirusproduct
		$a_01_7 = {70 61 79 6c 6f 61 64 22 3a } //2 payload":
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=16
 
}
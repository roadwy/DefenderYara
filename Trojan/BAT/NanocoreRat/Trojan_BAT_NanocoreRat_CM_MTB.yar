
rule Trojan_BAT_NanocoreRat_CM_MTB{
	meta:
		description = "Trojan:BAT/NanocoreRat.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 08 00 00 "
		
	strings :
		$a_81_0 = {52 75 6e 41 6e 74 69 41 6e 61 6c 79 73 69 73 } //5 RunAntiAnalysis
		$a_81_1 = {44 65 74 65 63 74 44 65 62 75 67 67 65 72 } //5 DetectDebugger
		$a_81_2 = {44 65 74 65 63 74 53 61 6e 64 62 6f 78 69 65 } //5 DetectSandboxie
		$a_81_3 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //2 Select * from Win32_ComputerSystem
		$a_81_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 57 48 45 52 45 20 50 72 6f 63 65 73 73 49 64 3d } //2 SELECT * FROM Win32_Process WHERE ProcessId=
		$a_81_5 = {53 43 48 54 41 53 4b 53 2e 65 78 65 20 2f 52 55 4e 20 2f 54 4e 20 22 } //2 SCHTASKS.exe /RUN /TN "
		$a_81_6 = {56 69 72 74 75 61 6c 42 6f 78 } //2 VirtualBox
		$a_81_7 = {76 6d 77 61 72 65 } //2 vmware
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2) >=23
 
}
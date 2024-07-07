
rule Backdoor_Win32_Mafion_gen_A{
	meta:
		description = "Backdoor:Win32/Mafion.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1c 00 0d 00 00 "
		
	strings :
		$a_00_0 = {53 70 65 63 69 61 6c 54 72 6f 6a 61 6e } //10 SpecialTrojan
		$a_00_1 = {43 2e 4f 2e 4e 2e 4e 2e 45 2e 43 2e 54 2e 45 2e 44 } //10 C.O.N.N.E.C.T.E.D
		$a_00_2 = {4f 70 65 6e 43 44 } //1 OpenCD
		$a_00_3 = {43 6c 6f 73 65 43 44 } //1 CloseCD
		$a_00_4 = {4d 6f 6e 69 74 6f 72 4f 4e } //1 MonitorON
		$a_00_5 = {42 6c 6f 63 6b 49 6e 70 75 74 } //1 BlockInput
		$a_00_6 = {53 68 75 74 64 6f 77 6e 4d 53 4e } //1 ShutdownMSN
		$a_00_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
		$a_00_8 = {46 69 6c 65 44 6f 77 6e 6c 6f 61 64 } //1 FileDownload
		$a_01_9 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_00_10 = {4b 69 6c 6c 50 72 6f 63 65 73 73 } //1 KillProcess
		$a_00_11 = {50 72 6f 63 65 73 73 20 74 6f 20 6b 69 6c 6c } //1 Process to kill
		$a_00_12 = {50 72 6f 7a 65 73 73 20 6b 69 6c 6c 65 64 } //1 Prozess killed
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=28
 
}

rule TrojanDownloader_Win32_Agent_ABG{
	meta:
		description = "TrojanDownloader:Win32/Agent.ABG,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe6 00 ffffffe3 00 10 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 52 45 43 59 43 4c 45 52 5c 73 79 73 74 65 6d 73 2e 63 6f 6d } //100 shellexecute=RECYCLER\systems.com
		$a_00_2 = {6f 70 65 6e 3d 73 79 73 74 65 6d 73 2e 63 6f 6d } //10 open=systems.com
		$a_00_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 73 79 73 74 65 6d 73 2e 63 6f 6d } //10 shellexecute=systems.com
		$a_00_4 = {73 68 65 6c 6c 5c 73 74 61 72 74 5c 63 6f 6d 6d 61 6e 64 3d 73 79 73 74 65 6d 73 2e 63 6f 6d } //10 shell\start\command=systems.com
		$a_00_5 = {73 68 65 6c 6c 5c 72 65 61 64 5c 63 6f 6d 6d 61 6e 64 3d 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //10 shell\read\command=explorer.exe
		$a_00_6 = {73 68 65 6c 6c 5c 73 74 61 72 74 5c 63 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c 73 79 73 74 65 6d 73 2e 63 6f 6d } //10 shell\start\command=RECYCLER\systems.com
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 73 79 73 74 65 6d } //1 Software\Microsoft\Windows\CurrentVersion\Policies\system
		$a_00_10 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 Explorer.exe
		$a_00_11 = {74 61 73 6b 6d 67 65 72 2e 63 6f 6d } //1 taskmger.com
		$a_01_12 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 } //1 DisableTaskmgr
		$a_01_13 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_00_14 = {5c 52 45 43 59 43 4c 45 52 5c 73 79 73 74 65 6d 73 2e 63 6f 6d } //1 \RECYCLER\systems.com
		$a_00_15 = {5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 6d 67 65 72 2e 63 6f 6d } //1 \system32\taskmger.com
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1) >=227
 
}

rule Trojan_Win32_Kilim_gen_D{
	meta:
		description = "Trojan:Win32/Kilim.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 77 77 2e 66 69 6c 6d 76 65 72 6d 65 2e 63 6f 6d } //01 00  GetDownload("http://www.filmverme.com
		$a_01_1 = {25 64 6f 6d 61 69 6e 25 2f 61 68 6b 2f 72 65 71 2e 70 68 70 3f 74 79 70 65 3d } //02 00  %domain%/ahk/req.php?type=
		$a_00_2 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65 20 2f 46 } //01 00  schtasks /Delete /TN GoogleUpdateTaskMachineCore /F
		$a_00_3 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 55 41 20 2f 46 } //01 00  schtasks /Delete /TN GoogleUpdateTaskMachineUA /F
		$a_00_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //01 00  taskkill /IM chrome.exe /F
		$a_00_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 62 72 6f 77 73 65 72 2e 65 78 65 20 2f 46 } //00 00  taskkill /IM browser.exe /F
	condition:
		any of ($a_*)
 
}
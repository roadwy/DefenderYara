
rule TrojanDownloader_Win32_Scar_D{
	meta:
		description = "TrojanDownloader:Win32/Scar.D,SIGNATURE_TYPE_PEHSTR_EXT,ffffff93 01 31 01 0a 00 00 "
		
	strings :
		$a_01_0 = {5a 77 4c 6f 61 64 44 72 69 76 65 72 } //100 ZwLoadDriver
		$a_01_1 = {5c 72 65 67 69 73 74 72 79 5c 6d 61 63 68 69 6e 65 5c 73 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //100 \registry\machine\system\CurrentControlSet\Services\
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //100 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {5c 5c 2e 5c 6d 79 62 72 } //100 \\.\mybr
		$a_01_4 = {56 33 4c 54 72 61 79 2e 65 78 65 } //1 V3LTray.exe
		$a_01_5 = {56 33 4c 53 76 63 2e 65 78 65 } //1 V3LSvc.exe
		$a_01_6 = {56 33 4c 45 78 65 63 2e 65 78 65 } //1 V3LExec.exe
		$a_01_7 = {41 59 41 67 65 6e 74 2e 61 79 65 } //1 AYAgent.aye
		$a_01_8 = {41 59 53 65 72 76 69 63 65 4e 54 2e 61 79 65 } //1 AYServiceNT.aye
		$a_01_9 = {4e 61 76 65 72 41 64 6d 69 6e 41 50 49 2e 65 78 65 } //1 NaverAdminAPI.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=305
 
}
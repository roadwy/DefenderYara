
rule TrojanDownloader_Win32_Agent_JF{
	meta:
		description = "TrojanDownloader:Win32/Agent.JF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 } //1 Software\Microsoft\Windows NT\CurrentVersion\Windows
		$a_02_1 = {68 74 74 70 3a 2f 2f 68 71 73 65 78 74 75 62 65 30 38 2e 63 6f 6d 2f 67 65 74 73 6f 66 74 2f 74 61 73 6b 2e 70 68 70 3f 76 3d [0-10] 26 71 3d } //1
		$a_00_2 = {5c 41 64 6f 62 65 5c 4d 61 6e 61 67 65 72 2e 65 78 65 } //1 \Adobe\Manager.exe
		$a_00_3 = {5c 63 72 63 2e 64 61 74 } //1 \crc.dat
		$a_00_4 = {6b 69 77 69 62 6f 74 } //1 kiwibot
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
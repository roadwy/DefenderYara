
rule TrojanDownloader_Win32_Agent_ACE{
	meta:
		description = "TrojanDownloader:Win32/Agent.ACE,SIGNATURE_TYPE_PEHSTR,52 00 52 00 0e 00 00 "
		
	strings :
		$a_01_0 = {73 74 31 2e 73 65 72 76 65 62 6c 6f 67 2e 6e 65 74 } //1 st1.serveblog.net
		$a_01_1 = {79 6c 6c 61 70 61 2e 6e 6f 2d 69 70 2e 69 6e 66 6f } //1 yllapa.no-ip.info
		$a_01_2 = {61 7a 38 2e 6e 6f 2d 69 70 2e 69 6e 66 6f } //1 az8.no-ip.info
		$a_01_3 = {7b 35 45 33 43 44 30 32 44 2d 32 33 46 37 2d 46 36 41 35 2d 44 30 42 41 2d 35 44 39 36 44 32 33 46 44 31 35 32 7d } //1 {5E3CD02D-23F7-F6A5-D0BA-5D96D23FD152}
		$a_01_4 = {7b 41 30 36 34 43 33 35 45 2d 32 39 41 43 2d 33 30 45 31 2d 31 43 31 39 2d 39 44 38 46 46 31 41 31 35 43 31 39 7d } //1 {A064C35E-29AC-30E1-1C19-9D8FF1A15C19}
		$a_01_5 = {7b 41 43 33 46 44 34 41 45 2d 36 34 36 30 2d 41 38 38 39 2d 42 35 42 41 2d 36 31 46 42 41 39 33 33 30 38 35 33 7d } //1 {AC3FD4AE-6460-A889-B5BA-61FBA9330853}
		$a_01_6 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 } //10 CONNECT %s:%i HTTP/1.0
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //10 SOFTWARE\Classes\http\shell\open\command
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_9 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 } //10 Software\Microsoft\Active Setup\Installed Components
		$a_01_11 = {61 64 76 70 61 63 6b } //10 advpack
		$a_01_12 = {53 74 75 62 50 61 74 68 } //10 StubPath
		$a_01_13 = {8b ec 81 c4 3c f2 ff ff 60 33 c0 8d bd 90 f2 ff ff b9 5b 0d 00 00 f3 aa 33 c0 8d bd 4c f2 ff ff b9 44 00 00 00 f3 aa c7 85 b9 f3 ff ff e6 00 00 00 e9 a6 13 00 00 55 8b ec 83 c4 d0 8b 75 08 68 11 27 34 06 ff b6 bb 0a 00 00 ff b6 e1 00 00 00 ff 96 dd 00 00 00 ff d0 89 86 bd 08 00 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10+(#a_01_13  & 1)*10) >=82
 
}
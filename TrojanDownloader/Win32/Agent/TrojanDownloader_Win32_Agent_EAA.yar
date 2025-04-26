
rule TrojanDownloader_Win32_Agent_EAA{
	meta:
		description = "TrojanDownloader:Win32/Agent.EAA,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {8b 1e 83 c6 04 51 e8 ?? ?? ?? ?? 59 01 45 ?? 89 07 83 c7 04 49 75 e9 } //2
		$a_01_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1 } //2
		$a_00_2 = {20 3e 6e 75 6c 20 32 3e 6e 75 6c 0d 0a } //1
		$a_00_3 = {40 72 64 20 2f 66 2f 73 2f 71 20 } //1 @rd /f/s/q 
		$a_00_4 = {40 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 } //1 @ping 127.0.0.1 -n 2
		$a_00_5 = {2e 77 69 6e 30 64 61 79 2e 63 6f 6d 2f } //1 .win0day.com/
		$a_00_6 = {20 46 69 6c 65 73 5c 75 70 64 61 74 65 2e 65 78 65 } //1  Files\update.exe
		$a_00_7 = {5c 77 69 6e 31 32 33 62 2e 62 61 74 } //1 \win123b.bat
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}
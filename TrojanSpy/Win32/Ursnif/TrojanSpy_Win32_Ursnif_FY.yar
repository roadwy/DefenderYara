
rule TrojanSpy_Win32_Ursnif_FY{
	meta:
		description = "TrojanSpy:Win32/Ursnif.FY,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0e 00 0d 00 00 "
		
	strings :
		$a_03_0 = {83 6d f8 64 8d 85 1c fd ff ff 50 ff 76 04 ff d3 83 7d f8 00 74 ?? 8b 45 fc 39 85 d4 fd ff ff } //4
		$a_01_1 = {8b c1 c6 44 30 01 00 8b 44 24 14 83 c0 2c 50 56 ff d7 8b 44 24 14 f6 00 10 74 } //2
		$a_03_2 = {8b d9 33 d8 d1 e8 f6 c3 01 74 ?? 35 20 83 b8 ed d1 e9 4a 75 eb } //2
		$a_01_3 = {2f 63 6f 6e 66 69 67 2e 70 68 70 } //2 /config.php
		$a_01_4 = {2f 64 61 74 61 2e 70 68 70 3f 76 65 72 73 69 6f 6e 3d } //2 /data.php?version=
		$a_01_5 = {2f 74 61 73 6b 2e 70 68 70 } //2 /task.php
		$a_01_6 = {4e 45 57 47 52 41 42 } //2 NEWGRAB
		$a_01_7 = {66 69 72 65 66 6f 78 2e 65 78 65 } //1 firefox.exe
		$a_01_8 = {63 68 72 6f 6d 65 2e 65 78 65 } //1 chrome.exe
		$a_01_9 = {6f 70 65 72 61 2e 65 78 65 } //1 opera.exe
		$a_01_10 = {73 61 66 61 72 69 2e 65 78 65 } //1 safari.exe
		$a_01_11 = {6e 65 63 65 73 73 61 72 79 70 72 6f 74 65 2e 63 6f 2e 63 63 } //1 necessaryprote.co.cc
		$a_01_12 = {6c 65 67 69 73 6c 61 74 69 6f 6e 6e 61 6d 65 2e 63 6f 2e 63 63 } //1 legislationname.co.cc
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=14
 
}

rule TrojanSpy_Win32_Stealer_ARA_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {74 65 73 74 74 74 74 74 2e 70 73 31 } //2 testtttt.ps1
		$a_01_1 = {50 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 72 65 6d 6f 74 65 73 69 67 6e 65 64 20 2d 46 69 6c 65 } //2 Powershell.exe -executionpolicy remotesigned -File
		$a_01_2 = {73 65 6e 64 73 20 74 68 65 20 75 73 65 72 6e 61 6d 65 2c 20 69 70 2c 20 63 75 72 72 65 6e 74 20 74 69 6d 65 2c 20 61 6e 64 20 64 61 74 65 20 6f 66 20 74 68 65 20 76 69 63 74 69 6d } //2 sends the username, ip, current time, and date of the victim
		$a_01_3 = {4c 6f 67 69 6e 20 44 61 74 61 } //2 Login Data
		$a_01_4 = {48 69 73 74 6f 72 79 } //2 History
		$a_01_5 = {77 65 62 68 6f 6f 6b } //2 webhook
		$a_01_6 = {53 79 73 74 65 6d 5f 49 4e 46 4f 2e 74 78 74 } //2 System_INFO.txt
		$a_01_7 = {6e 65 74 73 74 61 74 2e 74 78 74 } //2 netstat.txt
		$a_01_8 = {25 75 73 65 72 6e 61 6d 65 25 5f 43 61 70 74 75 72 65 2e 6a 70 67 } //2 %username%_Capture.jpg
		$a_01_9 = {70 72 6f 67 72 61 6d 6d 73 2e 74 78 74 } //2 programms.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=20
 
}
rule TrojanSpy_Win32_Stealer_ARA_MTB_2{
	meta:
		description = "TrojanSpy:Win32/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0f 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
		$a_80_2 = {57 69 6e 64 44 62 67 } //WindDbg  1
		$a_80_3 = {6f 6c 6c 79 44 62 67 } //ollyDbg  1
		$a_80_4 = {78 36 34 64 62 67 } //x64dbg  1
		$a_80_5 = {78 33 32 64 62 67 } //x32dbg  1
		$a_80_6 = {4f 62 73 69 64 69 61 6e 47 55 49 } //ObsidianGUI  1
		$a_80_7 = {49 6d 6d 44 62 67 } //ImmDbg  1
		$a_80_8 = {5a 65 74 61 20 44 65 62 75 67 67 65 72 } //Zeta Debugger  1
		$a_80_9 = {52 6f 63 6b 20 44 65 62 75 67 67 65 72 } //Rock Debugger  1
		$a_80_10 = {50 52 4f 47 52 41 4d 46 49 4c 45 53 } //PROGRAMFILES  1
		$a_80_11 = {5c 56 4d 57 61 72 65 5c } //\VMWare\  1
		$a_80_12 = {5c 6f 72 61 63 6c 65 5c 76 69 72 74 75 61 6c 62 6f 78 20 67 75 65 73 74 20 61 64 64 69 74 69 6f 6e 73 5c } //\oracle\virtualbox guest additions\  1
		$a_80_13 = {4d 3b 69 3b 63 3b 72 3b 6f 3b 73 3b 6f 3b 66 3b 74 3b 20 3b 45 3b 6e 3b 68 3b 61 3b 6e 3b 63 3b 65 3b 64 3b 20 3b 52 3b 53 3b 41 3b 20 3b 61 3b 6e 3b 64 3b 20 3b 41 3b 45 3b 53 3b 20 3b 43 3b 72 3b 79 3b 70 3b 74 3b 6f 3b 67 3b 72 3b 61 3b 70 3b 68 3b 69 3b 63 3b 20 3b 50 3b 72 3b 6f 3b 76 3b 69 3b 64 3b 65 3b 72 3b } //M;i;c;r;o;s;o;f;t; ;E;n;h;a;n;c;e;d; ;R;S;A; ;a;n;d; ;A;E;S; ;C;r;y;p;t;o;g;r;a;p;h;i;c; ;P;r;o;v;i;d;e;r;  2
		$a_80_14 = {41 6d 75 72 6e 63 61 77 65 6e 63 78 72 64 79 } //Amurncawencxrdy  2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*2+(#a_80_14  & 1)*2) >=17
 
}
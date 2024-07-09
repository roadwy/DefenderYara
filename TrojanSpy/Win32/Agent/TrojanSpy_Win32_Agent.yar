
rule TrojanSpy_Win32_Agent{
	meta:
		description = "TrojanSpy:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {e8 00 00 00 00 5f 33 f7 b8 a1 9f 40 00 8b c8 51 83 c0 32 c3 bb 00 10 40 00 81 eb 28 71 ff ff 53 75 05 33 c0 74 01 e9 fc b8 4b 9f } //10
		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 7e 54 65 6d 70 [0-04] 2e 74 6d 70 00 00 00 00 00 00 00 00 00 00 00 00 } //1
		$a_00_2 = {63 3a 5c 68 6f 6d 65 5c 6d 77 74 65 73 74 5c 74 6d 70 5c 77 2e 65 78 65 } //1 c:\home\mwtest\tmp\w.exe
		$a_00_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 31 2e 65 78 65 } //1 c:\windows\system32\1.exe
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}
rule TrojanSpy_Win32_Agent_2{
	meta:
		description = "TrojanSpy:Win32/Agent,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 63 76 68 6f 73 74 2e 65 78 65 } //1 WINDOWS\system32\scvhost.exe
		$a_01_2 = {76 69 72 74 75 61 6c 2d 6e 65 74 2e 70 69 73 65 6d 2e 73 75 2f 4e 69 63 6b 2e 67 69 66 } //1 virtual-net.pisem.su/Nick.gif
		$a_01_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule TrojanSpy_Win32_Agent_3{
	meta:
		description = "TrojanSpy:Win32/Agent,SIGNATURE_TYPE_PEHSTR,03 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 3a 5c 73 6f 75 72 63 65 5c 63 67 5c 63 67 61 6c 6c 5c 77 6d 67 6a 5c 77 6d 67 6a 65 78 65 } //1 f:\source\cg\cgall\wmgj\wmgjexe
		$a_01_1 = {63 6d 64 3d 31 26 75 73 72 6e 61 6d 65 3d 25 73 26 75 73 72 70 61 73 73 3d 25 73 26 73 65 72 76 65 72 6e 61 6d 65 3d 25 73 26 62 61 6e 6b 70 61 73 73 3d 25 73 26 6e 69 63 6b 6e 61 6d 65 3d 25 73 26 72 61 6e 6b 69 6e 66 6f 3d 25 64 } //1 cmd=1&usrname=%s&usrpass=%s&servername=%s&bankpass=%s&nickname=%s&rankinfo=%d
		$a_01_2 = {41 43 54 49 4f 4e 5f 4f 46 46 4c 49 4e 45 5f 43 4c 49 45 4e 54 } //1 ACTION_OFFLINE_CLIENT
		$a_01_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 77 69 74 68 20 50 49 4e 43 4f 44 45 2d 76 61 6c 75 65 20 66 61 75 6c 74 2c 20 63 6f 64 65 20 3d 20 25 64 } //1 ReadProcessMemory with PINCODE-value fault, code = %d
		$a_01_4 = {73 7a 41 63 63 6f 75 6e 74 20 3d 20 25 73 } //1 szAccount = %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}
rule TrojanSpy_Win32_Agent_4{
	meta:
		description = "TrojanSpy:Win32/Agent,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {42 00 6f 00 6e 00 75 00 73 00 20 00 31 00 2e 00 65 00 78 00 65 00 } //1 Bonus 1.exe
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6d 00 72 00 2d 00 6d 00 6f 00 6e 00 65 00 79 00 73 00 2e 00 6f 00 72 00 67 00 2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 6c 00 69 00 6e 00 65 00 2e 00 67 00 69 00 66 00 } //1 http://wmr-moneys.org/config/line.gif
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 6f 00 75 00 6e 00 74 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 6c 00 69 00 6e 00 65 00 2e 00 67 00 69 00 66 00 } //1 http://countexchange.com/config/line.gif
		$a_01_3 = {3f 00 61 00 3d 00 77 00 6d 00 6b 00 3a 00 70 00 61 00 79 00 74 00 6f 00 3f 00 50 00 75 00 72 00 73 00 65 00 3d 00 } //1 ?a=wmk:payto?Purse=
		$a_01_4 = {26 00 41 00 6d 00 6f 00 75 00 6e 00 74 00 3d 00 } //1 &Amount=
		$a_01_5 = {26 00 44 00 65 00 73 00 63 00 3d 00 } //1 &Desc=
		$a_01_6 = {5c 00 42 00 6f 00 6e 00 75 00 73 00 20 00 31 00 2e 00 35 00 2e 00 76 00 62 00 70 00 } //1 \Bonus 1.5.vbp
		$a_01_7 = {5c 00 53 00 4f 00 46 00 54 00 32 00 } //1 \SOFT2
		$a_01_8 = {2a 00 5c 00 41 00 47 00 3a 00 5c 00 56 00 6c 00 61 00 64 00 69 00 6d 00 69 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 } //1 *\AG:\Vladimir\Desktop\
		$a_01_9 = {57 65 62 4d 6f 6e 65 79 } //1 WebMoney
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
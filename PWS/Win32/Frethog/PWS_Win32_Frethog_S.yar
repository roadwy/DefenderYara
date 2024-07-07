
rule PWS_Win32_Frethog_S{
	meta:
		description = "PWS:Win32/Frethog.S,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 43 50 54 20 54 4f 3a 3c } //1 RCPT TO:<
		$a_01_1 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //1 MAIL FROM:<
		$a_01_2 = {48 45 4c 4f } //1 HELO
		$a_01_3 = {67 5f 68 68 6f 6f 6b 20 3d 3d } //2 g_hhook ==
		$a_01_4 = {6d 61 70 70 69 6e 67 00 00 43 61 6e 27 74 20 6d } //2 慭灰湩g䌀湡琧洠
		$a_01_5 = {73 6d 74 70 00 00 00 00 74 63 70 00 } //2
		$a_01_6 = {75 6e 65 73 74 2e 6e 65 74 3c 6d 69 72 } //4 unest.net<mir
		$a_01_7 = {53 65 74 44 49 50 53 48 6f 6f 6b } //4 SetDIPSHook
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*4+(#a_01_7  & 1)*4) >=11
 
}
rule PWS_Win32_Frethog_S_2{
	meta:
		description = "PWS:Win32/Frethog.S,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 0e 00 00 "
		
	strings :
		$a_00_0 = {6d 79 61 70 70 2e 65 78 65 20 2f 63 20 64 65 6c 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 } //1 myapp.exe /c del "C:\myapp.exe"
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4e 65 74 4d 65 65 74 69 6e 67 5c 72 61 76 79 74 6d 6f 6e 2e 63 66 67 } //1 C:\Program Files\NetMeeting\ravytmon.cfg
		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4e 65 74 4d 65 65 74 69 6e 67 5c 72 61 76 79 74 6d 6f 6e 2e 65 78 65 } //1 C:\Program Files\NetMeeting\ravytmon.exe
		$a_00_3 = {61 76 70 2e 65 78 65 } //1 avp.exe
		$a_00_4 = {7a 68 65 6e 67 74 75 2e 64 61 74 } //1 zhengtu.dat
		$a_00_5 = {4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //1 MZKERNEL32.DLL
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_8 = {73 74 72 72 63 68 72 } //1 strrchr
		$a_01_9 = {41 56 50 2e 54 72 61 66 66 69 63 4d 6f 6e 43 6f 6e 6e 65 63 74 69 6f 6e 54 65 72 6d } //1 AVP.TrafficMonConnectionTerm
		$a_00_10 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 AVP.Product_Notification
		$a_00_11 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 67 } //1 AVP.AlertDialog
		$a_01_12 = {41 56 50 2e 42 75 74 74 6f 6e } //1 AVP.Button
		$a_00_13 = {23 33 32 37 37 30 } //1 #32770
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_01_12  & 1)*1+(#a_00_13  & 1)*1) >=13
 
}
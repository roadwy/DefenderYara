
rule TrojanSpy_Win32_Kaliox_A{
	meta:
		description = "TrojanSpy:Win32/Kaliox.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 47 6f } //1 ProcGo
		$a_01_1 = {47 65 74 46 69 6c 65 } //1 GetFile
		$a_01_2 = {5c 50 72 69 6e 74 65 72 5c 4b 65 79 2e 69 6e 69 } //1 \Printer\Key.ini
		$a_01_3 = {2f 53 53 65 6e 64 4e 65 74 77 6f 72 6b 49 6e 66 6f 4c 69 73 74 2e 61 73 70 3f 48 6f 73 74 49 44 3d } //1 /SSendNetworkInfoList.asp?HostID=
		$a_01_4 = {2f 53 52 65 61 64 55 70 6c 6f 61 64 46 69 6c 65 4e 75 2e 61 73 70 3f 48 6f 73 74 49 44 3d } //1 /SReadUploadFileNu.asp?HostID=
		$a_01_5 = {53 54 41 52 54 53 50 59 } //1 STARTSPY
		$a_01_6 = {3f 48 6f 73 74 49 44 3d 00 26 4f 6e 6c 69 6e 65 53 74 61 74 3d 00 } //1 䠿獯䥴㵄☀湏楬敮瑓瑡=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}

rule Backdoor_Win32_PcClient_CE{
	meta:
		description = "Backdoor:Win32/PcClient.CE,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8d 00 ffffff8d 00 10 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 } //10 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)
		$a_00_1 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 30 38 64 } //10 http://%s:%d/%s%d%08d
		$a_00_2 = {69 6e 64 65 78 2e 61 73 70 3f } //10 index.asp?
		$a_00_3 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c } //10 CurrentControlSet\
		$a_00_4 = {43 6f 6e 74 72 6f 6c 53 65 74 30 30 33 5c } //10 ControlSet003\
		$a_00_5 = {43 6f 6e 74 72 6f 6c 53 65 74 30 30 32 5c } //10 ControlSet002\
		$a_00_6 = {43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c } //10 ControlSet001\
		$a_00_7 = {53 56 43 48 4f 53 54 2e 45 58 45 } //10 SVCHOST.EXE
		$a_00_8 = {53 45 4c 4f 41 44 44 72 69 76 65 72 50 72 69 76 69 6c 65 67 65 } //10 SELOADDriverPrivilege
		$a_00_9 = {4c 6f 61 64 50 72 6f 66 69 6c 65 } //10 LoadProfile
		$a_00_10 = {53 65 6e 73 4e 6f 74 69 66 79 4e 65 74 63 6f 6e 45 76 65 6e 74 } //10 SensNotifyNetconEvent
		$a_00_11 = {53 65 6e 73 4e 6f 74 69 66 79 52 61 73 45 76 65 6e 74 } //10 SensNotifyRasEvent
		$a_00_12 = {53 65 6e 73 4e 6f 74 69 66 79 57 69 6e 6c 6f 67 6f 6e 45 76 65 6e 74 } //10 SensNotifyWinlogonEvent
		$a_00_13 = {53 65 72 76 69 63 65 4d 61 69 6e } //10 ServiceMain
		$a_00_14 = {8d 85 fc fe ff ff 68 20 51 00 10 50 89 7d fc ff d6 59 85 c0 59 74 0d 8d 45 fc 50 57 57 68 02 2d 00 10 eb 1f 8d 85 fc fe ff ff 68 14 51 00 10 50 ff d6 59 85 c0 59 74 13 8d 45 fc 50 57 57 68 39 2d 00 10 57 57 ff 15 } //1
		$a_02_15 = {8d 85 fc fe ff ff 68 14 51 00 10 50 89 7d fc ff 15 90 01 04 59 85 c0 59 74 13 8d 45 fc 50 57 57 68 98 2d 00 10 57 57 ff 15 90 01 04 6a 01 58 5f 5e 5b c9 c3 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*10+(#a_00_10  & 1)*10+(#a_00_11  & 1)*10+(#a_00_12  & 1)*10+(#a_00_13  & 1)*10+(#a_00_14  & 1)*1+(#a_02_15  & 1)*1) >=141
 
}
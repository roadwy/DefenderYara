
rule Trojan_Win32_Emotetcrypt_HK_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0f 00 00 "
		
	strings :
		$a_03_0 = {2b ca 2b 0d 90 01 04 8b 15 90 01 04 2b c8 8d 8c 8f 00 10 00 00 8d 04 95 00 20 00 00 0b c8 51 56 55 ff 15 90 00 } //1
		$a_81_1 = {66 6f 6c 64 65 72 2e 64 6c 6c } //1 folder.dll
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 43 6c 61 73 73 } //1 DllRegisterClass
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_4 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_5 = {68 68 63 74 72 6c 2e 6f 63 78 } //1 hhctrl.ocx
		$a_81_6 = {43 6f 6c 6f 72 53 65 6c 65 63 74 6f 72 20 4d 46 43 20 41 70 70 6c 69 63 61 74 69 6f 6e } //1 ColorSelector MFC Application
		$a_81_7 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_81_8 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 NoRecentDocsHistory
		$a_81_9 = {4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b } //1 NoEntireNetwork
		$a_81_10 = {4e 6f 42 61 63 6b 42 75 74 74 6f 6e } //1 NoBackButton
		$a_81_11 = {4e 6f 50 6c 61 63 65 73 42 61 72 } //1 NoPlacesBar
		$a_81_12 = {4e 6f 52 65 6d 6f 76 65 } //1 NoRemove
		$a_81_13 = {4e 6f 44 72 69 76 65 73 } //1 NoDrives
		$a_03_14 = {0f b6 04 30 03 c3 99 bb 90 01 04 f7 fb 03 54 24 90 01 01 8b da 8b 54 24 90 01 01 8a 04 32 8b 54 24 90 01 01 0f b6 14 1a 88 14 2e 8b 54 24 90 01 01 88 04 1a 8b 44 24 90 01 01 0f b6 04 30 8b 54 24 90 01 01 0f b6 14 1a 03 c2 99 bd 90 01 04 f7 fd 8b 44 24 90 01 01 8b 6c 24 90 01 01 03 d7 0f b6 14 02 30 54 29 90 00 } //14
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_03_14  & 1)*14) >=14
 
}
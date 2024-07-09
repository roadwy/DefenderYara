
rule Trojan_Win32_Emotetcrypt_HM_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3f 00 3f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {03 d5 2b d0 b8 00 04 00 00 2b c1 03 c0 03 c0 81 c2 00 10 00 00 03 c0 0b d0 52 57 53 ff 15 } //50
		$a_03_1 = {8d bc ab 00 10 00 00 8d 5a 02 0f af 1d ?? ?? ?? ?? 2b 1d ?? ?? ?? ?? 2b 1d ?? ?? ?? ?? 03 da 8d 84 58 00 20 00 00 0b f8 57 56 6a 00 ff 15 } //50
		$a_81_2 = {70 68 69 6e 6c 2e 64 6c 6c } //1 phinl.dll
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 43 6c 61 73 73 } //1 DllRegisterClass
		$a_81_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_5 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_6 = {68 68 63 74 72 6c 2e 6f 63 78 } //1 hhctrl.ocx
		$a_81_7 = {43 6f 6c 6f 72 53 65 6c 65 63 74 6f 72 20 4d 46 43 20 41 70 70 6c 69 63 61 74 69 6f 6e } //1 ColorSelector MFC Application
		$a_81_8 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_81_9 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 NoRecentDocsHistory
		$a_81_10 = {4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b } //1 NoEntireNetwork
		$a_81_11 = {4e 6f 42 61 63 6b 42 75 74 74 6f 6e } //1 NoBackButton
		$a_81_12 = {4e 6f 50 6c 61 63 65 73 42 61 72 } //1 NoPlacesBar
		$a_81_13 = {4e 6f 52 65 6d 6f 76 65 } //1 NoRemove
		$a_81_14 = {4e 6f 44 72 69 76 65 73 } //1 NoDrives
	condition:
		((#a_01_0  & 1)*50+(#a_03_1  & 1)*50+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=63
 
}
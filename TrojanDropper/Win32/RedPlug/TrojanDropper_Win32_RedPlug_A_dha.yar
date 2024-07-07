
rule TrojanDropper_Win32_RedPlug_A_dha{
	meta:
		description = "TrojanDropper:Win32/RedPlug.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0a 00 00 "
		
	strings :
		$a_03_0 = {00 99 b9 1a 00 00 00 f7 f9 46 80 c2 41 88 54 35 90 01 01 83 fe 64 7c 90 00 } //10
		$a_01_1 = {63 70 6c 75 73 70 6c 75 73 5f 6d 65 } //1 cplusplus_me
		$a_01_2 = {4c 6f 63 61 6c 20 41 70 70 57 69 7a 61 72 64 2d 47 65 6e 65 72 61 74 65 64 20 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //1 Local AppWizard-Generated Applications
		$a_01_3 = {46 6f 72 63 65 52 65 6d 6f 76 65 } //1 ForceRemove
		$a_01_4 = {4e 6f 52 65 6d 6f 76 65 } //1 NoRemove
		$a_01_5 = {4e 6f 52 75 6e } //1 NoRun
		$a_01_6 = {4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b } //1 NoEntireNetwork
		$a_01_7 = {4e 6f 46 69 6c 65 4d 72 75 } //1 NoFileMru
		$a_01_8 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_01_9 = {4e 6f 50 6c 61 63 65 73 42 61 72 } //1 NoPlacesBar
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=13
 
}
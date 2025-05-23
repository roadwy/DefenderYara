
rule Trojan_Win32_Emotet_BE{
	meta:
		description = "Trojan:Win32/Emotet.BE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 72 65 6c 5c 69 4d 53 2d 73 72 76 72 65 67 35 36 2e 70 64 62 } //1 \rel\iMS-srvreg56.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BE_2{
	meta:
		description = "Trojan:Win32/Emotet.BE,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0f 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 6e 33 32 2e 70 64 62 } //10 Chen32.pdb
		$a_01_1 = {6d 33 4b 48 4c 4d 63 46 2e 70 64 62 } //10 m3KHLMcF.pdb
		$a_01_2 = {72 53 56 7a 2f 66 39 3d 47 49 30 2e 70 64 62 } //10 rSVz/f9=GI0.pdb
		$a_01_3 = {40 64 4d 6c 45 7c 76 4b 70 71 2e 70 64 62 } //10 @dMlE|vKpq.pdb
		$a_01_4 = {53 4b 52 46 4d 2e 70 64 62 } //10 SKRFM.pdb
		$a_01_5 = {66 6f 72 51 69 73 61 6c 65 78 } //1 forQisalex
		$a_01_6 = {6a 65 73 73 69 63 61 71 47 6f 6f 67 6c 65 6a 43 44 } //1 jessicaqGooglejCD
		$a_00_7 = {73 00 6f 00 6d 00 65 00 77 00 68 00 61 00 74 00 6d 00 47 00 43 00 68 00 72 00 6f 00 6d 00 65 00 48 00 } //1 somewhatmGChromeH
		$a_00_8 = {6c 00 69 00 66 00 65 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2e 00 77 00 61 00 73 00 54 00 68 00 65 00 63 00 64 00 6d 00 } //1 lifebrowser.wasThecdm
		$a_00_9 = {66 00 69 00 6e 00 64 00 20 00 66 00 69 00 72 00 73 00 74 00 20 00 62 00 69 00 67 00 20 00 76 00 61 00 6c 00 75 00 65 00 } //1 find first big value
		$a_00_10 = {4c 00 76 00 45 00 77 00 45 00 4e 00 20 00 74 00 65 00 4c 00 67 00 64 00 79 00 20 00 42 00 74 00 20 00 57 00 56 00 56 00 48 00 4c 00 55 00 20 00 6c 00 74 00 48 00 65 00 55 00 } //1 LvEwEN teLgdy Bt WVVHLU ltHeU
		$a_00_11 = {6e 00 6d 00 63 00 6f 00 67 00 61 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 nmcogame.dll
		$a_00_12 = {4e 00 65 00 78 00 6f 00 6e 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 20 00 47 00 61 00 6d 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 NexonMessenger Game Service
		$a_00_13 = {4e 00 61 00 6d 00 65 00 73 00 70 00 63 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 Namespc2.dll
		$a_00_14 = {4c 00 6f 00 67 00 69 00 74 00 65 00 63 00 68 00 20 00 51 00 75 00 69 00 63 00 6b 00 43 00 61 00 6d 00 } //1 Logitech QuickCam
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1) >=12
 
}
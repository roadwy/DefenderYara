
rule TrojanClicker_Win32_VB_DH{
	meta:
		description = "TrojanClicker:Win32/VB.DH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 6c 69 63 6b 5c 43 6c 69 63 6b 2e 44 6c 6c } //1 Click\Click.Dll
		$a_01_1 = {43 6c 69 63 6b 4d 6f 64 75 6c 65 } //1 ClickModule
		$a_01_2 = {4a 69 6e 43 68 65 6e 67 4d 6f 64 75 6c 65 } //1 JinChengModule
		$a_01_3 = {42 69 61 6f 54 69 4d 6f 64 75 6c 65 } //1 BiaoTiModule
		$a_01_4 = {3f 00 63 00 6f 00 6d 00 65 00 49 00 44 00 3d 00 } //1 ?comeID=
		$a_01_5 = {74 00 61 00 6e 00 6b 00 72 00 65 00 67 00 2e 00 64 00 6f 00 3f 00 73 00 69 00 64 00 3d 00 } //1 tankreg.do?sid=
		$a_01_6 = {41 00 64 00 6f 00 64 00 62 00 2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 } //1 Adodb.Stream
		$a_01_7 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 } //1 Microsoft.XMLHTTP
		$a_01_8 = {52 00 65 00 61 00 64 00 79 00 53 00 74 00 61 00 74 00 65 00 } //1 ReadyState
		$a_01_9 = {72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 42 00 6f 00 64 00 79 00 } //1 responseBody
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}

rule TrojanSpy_Win32_Maran_AV{
	meta:
		description = "TrojanSpy:Win32/Maran.AV,SIGNATURE_TYPE_PEHSTR,fffffff1 00 fffffff1 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {64 65 6c 20 64 65 6c 70 6c 6d 65 2e 62 61 74 } //20 del delplme.bat
		$a_01_2 = {40 65 63 68 6f 20 6f 66 66 } //20 @echo off
		$a_01_3 = {67 6f 74 6f 20 6c 6f 6f 70 } //20 goto loop
		$a_01_4 = {6f 64 33 6d 64 69 2e 64 6c 6c } //20 od3mdi.dll
		$a_01_5 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //20 \\.\PhysicalDrive0
		$a_01_6 = {4d 00 53 00 41 00 46 00 44 00 20 00 54 00 63 00 70 00 69 00 70 00 20 00 5b 00 54 00 43 00 50 00 2f 00 49 00 50 00 5d 00 } //20 MSAFD Tcpip [TCP/IP]
		$a_01_7 = {61 76 70 2e 65 78 65 00 } //20
		$a_01_8 = {69 70 66 69 6c 74 65 72 } //1 ipfilter
		$a_01_9 = {41 75 64 69 6f 20 41 64 61 70 74 65 72 } //1 Audio Adapter
		$a_01_10 = {55 42 55 4e 54 55 58 } //1 UBUNTUX
		$a_01_11 = {56 47 41 44 6f 77 6e } //1 VGADown
		$a_01_12 = {56 6f 69 63 65 4d 61 6e 61 67 65 72 44 6f 77 6e } //1 VoiceManagerDown
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=241
 
}
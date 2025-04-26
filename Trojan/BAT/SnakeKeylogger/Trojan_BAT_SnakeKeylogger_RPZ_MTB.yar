
rule Trojan_BAT_SnakeKeylogger_RPZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {30 00 79 00 74 00 68 00 2f 00 5a 00 64 00 69 00 69 00 63 00 45 00 79 00 37 00 41 00 78 00 57 00 75 00 54 00 59 00 48 00 55 00 77 00 3d 00 3d 00 } //1 0yth/ZdiicEy7AxWuTYHUw==
		$a_01_1 = {6a 00 6a 00 73 00 32 00 44 00 4c 00 2f 00 5a 00 4e 00 77 00 6d 00 35 00 76 00 65 00 59 00 38 00 42 00 70 00 75 00 71 00 76 00 41 00 51 00 71 00 43 00 76 00 38 00 7a 00 77 00 56 00 79 00 42 00 64 00 49 00 54 00 2b 00 48 00 69 00 4d 00 73 00 54 00 73 00 34 00 3d 00 } //1 jjs2DL/ZNwm5veY8BpuqvAQqCv8zwVyBdIT+HiMsTs4=
		$a_01_2 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 cdn.discordapp.com
		$a_01_3 = {55 00 71 00 6e 00 6e 00 6a 00 68 00 2e 00 64 00 61 00 74 00 } //1 Uqnnjh.dat
		$a_01_4 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_7 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_SnakeKeylogger_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 4b 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //1 WinKeyLogger
		$a_01_1 = {41 00 75 00 74 00 6f 00 73 00 74 00 61 00 72 00 74 00 20 00 4c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 } //1 Autostart Logging
		$a_01_2 = {6c 00 6f 00 67 00 64 00 69 00 72 00 } //1 logdir
		$a_01_3 = {57 72 69 74 65 4c 6f 67 } //1 WriteLog
		$a_01_4 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_5 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b } //1 AsyncCallback
		$a_01_6 = {4c 69 62 4b 65 79 48 6f 6f 6b } //1 LibKeyHook
		$a_01_7 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //1 GetForegroundWindow
		$a_01_8 = {4d 6f 75 73 65 45 76 65 6e 74 41 72 67 73 } //1 MouseEventArgs
		$a_01_9 = {46 6f 72 6d 43 6c 6f 73 69 6e 67 45 76 65 6e 74 41 72 67 73 } //1 FormClosingEventArgs
		$a_01_10 = {43 61 6e 63 65 6c 45 76 65 6e 74 41 72 67 73 } //1 CancelEventArgs
		$a_01_11 = {4b 65 79 44 6f 77 6e 45 76 65 6e 74 41 72 67 73 } //1 KeyDownEventArgs
		$a_01_12 = {4b 65 79 55 70 45 76 65 6e 74 41 72 67 73 } //1 KeyUpEventArgs
		$a_01_13 = {4b 65 79 44 6f 77 6e 41 6e 64 55 70 45 76 65 6e 74 41 72 67 73 } //1 KeyDownAndUpEventArgs
		$a_01_14 = {4b 65 79 44 65 74 65 63 74 6f 72 } //1 KeyDetector
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}
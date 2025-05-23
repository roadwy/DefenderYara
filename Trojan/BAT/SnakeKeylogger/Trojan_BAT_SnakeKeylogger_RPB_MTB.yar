
rule Trojan_BAT_SnakeKeylogger_RPB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {73 00 75 00 62 00 71 00 74 00 61 00 6e 00 65 00 6f 00 75 00 73 00 73 00 68 00 6f 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-30] 2e 00 70 00 6e 00 67 00 } //1
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_5 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_6 = {47 65 74 49 6e 76 6f 63 61 74 69 6f 6e 4c 69 73 74 } //1 GetInvocationList
		$a_01_7 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_SnakeKeylogger_RPB_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 00 38 00 2e 00 31 00 37 00 39 00 2e 00 31 00 31 00 31 00 2e 00 32 00 34 00 30 00 } //1 18.179.111.240
		$a_01_1 = {6c 00 6f 00 61 00 64 00 65 00 72 00 } //1 loader
		$a_01_2 = {75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 } //1 uploads
		$a_01_3 = {47 00 70 00 73 00 65 00 70 00 71 00 7a 00 78 00 2e 00 6a 00 70 00 67 00 } //1 Gpsepqzx.jpg
		$a_01_4 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 32 00 30 00 } //1 /c timeout 20
		$a_01_5 = {52 00 66 00 74 00 61 00 6d 00 61 00 6a 00 6e 00 71 00 6f 00 71 00 77 00 6f 00 63 00 64 00 69 00 77 00 66 00 72 00 77 00 2e 00 48 00 65 00 61 00 73 00 65 00 7a 00 66 00 76 00 76 00 68 00 } //1 Rftamajnqoqwocdiwfrw.Heasezfvvh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_SnakeKeylogger_RPB_MTB_3{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 00 75 00 52 00 5c 00 6e 00 6f 00 69 00 73 00 72 00 65 00 56 00 74 00 6e 00 65 00 72 00 72 00 75 00 43 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 65 00 72 00 61 00 77 00 74 00 66 00 6f 00 53 00 } //1 nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_01_1 = {4b 00 55 00 7a 00 59 00 42 00 38 00 63 00 71 00 76 00 6a 00 4f 00 6d 00 4c 00 62 00 31 00 68 00 49 00 74 00 4a 00 6e 00 57 00 4c 00 49 00 36 00 56 00 61 00 31 00 71 00 7a 00 79 00 62 00 66 00 75 00 78 00 72 00 32 00 38 00 6c 00 6c 00 66 00 37 00 47 00 67 00 69 00 6c 00 42 00 57 00 53 00 6a 00 4d 00 76 00 6c 00 34 00 46 00 6f 00 38 00 6d 00 } //1 KUzYB8cqvjOmLb1hItJnWLI6Va1qzybfuxr28llf7GgilBWSjMvl4Fo8m
		$a_01_2 = {43 61 70 74 61 69 6e 42 72 69 } //1 CaptainBri
		$a_01_3 = {54 69 63 6b 43 6f 75 6e 74 } //1 TickCount
		$a_01_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_5 = {52 43 34 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 } //1 RC4EncryptDecrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_SnakeKeylogger_RPB_MTB_4{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-50] 43 00 68 00 72 00 6f 00 6d 00 65 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 2e 00 65 00 78 00 65 00 } //1
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_4 = {76 00 6d 00 77 00 61 00 72 00 65 00 } //1 vmware
		$a_01_5 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 } //1 VirtualBox
		$a_01_6 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 20 00 69 00 73 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 } //1 Password Grabber is disabled
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_8 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_9 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_10 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_11 = {53 6c 65 65 70 } //1 Sleep
		$a_01_12 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
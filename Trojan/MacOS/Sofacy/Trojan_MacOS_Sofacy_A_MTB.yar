
rule Trojan_MacOS_Sofacy_A_MTB{
	meta:
		description = "Trojan:MacOS/Sofacy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 61 70 70 6c 65 2e 75 70 64 61 74 65 72 2e 70 6c 69 73 74 } //1 /Library/LaunchAgents/com.apple.updater.plist
		$a_00_1 = {3c 73 74 72 69 6e 67 3e 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 64 75 66 68 3c 2f 73 74 72 69 6e 67 3e } //1 <string>/Users/Shared/dufh</string>
		$a_00_2 = {2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 73 74 61 72 74 2e 73 68 } //1 /Users/Shared/start.sh
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_MacOS_Sofacy_A_MTB_2{
	meta:
		description = "Trojan:MacOS/Sofacy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8d 8d 48 fd ff ff 31 d2 89 d7 4c 8d 85 58 fd ff ff 4c 8d 4d e0 89 45 ec 48 c7 85 48 fd ff ff 88 02 00 00 48 89 bd 40 fd ff ff 4c 89 cf 4c 89 c2 4c 8b 85 40 fd ff ff 4c 8b 8d 40 fd ff ff e8 90 25 00 00 89 85 54 fd ff ff 81 bd 54 fd ff ff 00 00 00 00 41 0f 94 c2 41 80 f2 01 41 80 e2 01 41 0f b6 c2 89 c1 48 81 f9 00 00 00 00 0f 84 1f 00 00 00 48 8d 3d 93 2d 00 00 48 8d 35 9d 2d 00 00 ba 21 00 00 00 48 8d 0d c7 2d 00 00 e8 76 24 00 00 } //1
		$a_00_1 = {4c 6f 61 64 65 72 57 69 6e 41 70 69 2f 4c 6f 61 64 65 72 57 69 6e 41 70 69 2f 6d 61 69 6e 2e 6d 6d } //1 LoaderWinApi/LoaderWinApi/main.mm
		$a_00_2 = {4d 61 63 20 4f 53 20 58 20 2d 20 25 73 20 25 73 0a 55 73 65 72 20 6e 61 6d 65 20 2d 20 25 73 0a 09 09 09 09 09 09 50 72 6f 63 65 73 73 20 6c 69 73 74 } //1
		$a_00_3 = {41 6d 49 42 65 69 6e 67 44 65 62 75 67 67 65 64 } //1 AmIBeingDebugged
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
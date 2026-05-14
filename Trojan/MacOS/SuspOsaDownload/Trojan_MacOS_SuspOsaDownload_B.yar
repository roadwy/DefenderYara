
rule Trojan_MacOS_SuspOsaDownload_B{
	meta:
		description = "Trojan:MacOS/SuspOsaDownload.B,SIGNATURE_TYPE_MACHOHSTR_EXT,0f 00 0f 00 09 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 61 6c 6c 20 54 65 72 6d 69 6e 61 6c } //2 killall Terminal
		$a_02_1 = {3c 6b 65 79 3e 52 75 6e 41 74 4c 6f 61 64 3c 2f 6b 65 79 3e [0-20] 3c 74 72 75 65 2f 3e } //2
		$a_00_2 = {3c 73 74 72 69 6e 67 3e 2f 75 73 72 2f 62 69 6e 2f 6f 73 61 73 63 72 69 70 74 3c 2f 73 74 72 69 6e 67 3e } //2 <string>/usr/bin/osascript</string>
		$a_00_3 = {64 6f 20 73 68 65 6c 6c 20 73 63 72 69 70 74 20 22 63 75 72 6c 20 2d 73 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 } //2 do shell script "curl -s https://t.me
		$a_00_4 = {2f 61 70 69 2e 70 68 70 3f 63 68 65 63 6b 3d } //2 /api.php?check=
		$a_00_5 = {67 65 74 2e 70 68 70 3f 6f 69 64 3d } //2 get.php?oid=
		$a_00_6 = {20 7c 20 6f 73 61 73 63 72 69 70 74 } //2  | osascript
		$a_00_7 = {6c 61 75 6e 63 68 63 74 6c 20 6c 6f 61 64 20 25 73 2f 63 6f 6d 2e } //1 launchctl load %s/com.
		$a_00_8 = {6c 61 75 6e 63 68 63 74 6c 20 6c 6f 61 64 20 7e 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e } //1 launchctl load ~/Library/LaunchAgents/com.
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=15
 
}
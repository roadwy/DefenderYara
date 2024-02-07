
rule Trojan_Win32_bosbot_A{
	meta:
		description = "Trojan:Win32/bosbot.A,SIGNATURE_TYPE_PEHSTR_EXT,72 00 72 00 0a 00 00 64 00 "
		
	strings :
		$a_00_0 = {48 65 6c 6c 6f 2c 20 4b 75 47 6f 75 21 } //0a 00  Hello, KuGou!
		$a_02_1 = {68 74 74 70 3a 2f 2f 63 6f 75 6e 74 2e 6b 65 79 35 31 38 38 2e 63 6f 6d 2f 90 02 10 2f 90 02 10 2e 61 73 70 90 00 } //0a 00 
		$a_02_2 = {64 6f 77 6e 75 72 6c 3d 68 74 74 70 3a 2f 2f 90 02 10 2e 63 6f 6d 2f 63 6f 75 6e 74 2e 74 78 74 90 00 } //0a 00 
		$a_02_3 = {64 6f 77 6e 75 72 6c 3d 68 74 74 70 3a 2f 2f 90 02 10 2e 63 6e 2f 90 02 08 2e 74 78 74 90 00 } //01 00 
		$a_00_4 = {44 69 73 61 62 6c 65 57 69 6e 64 6f 77 73 55 70 64 61 74 65 41 63 63 65 73 73 } //01 00  DisableWindowsUpdateAccess
		$a_00_5 = {70 6f 70 75 72 6c 74 69 6d 65 3d } //01 00  popurltime=
		$a_02_6 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 90 02 08 2e 65 78 65 90 00 } //01 00 
		$a_02_7 = {65 78 65 66 69 6c 65 3d 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 90 02 08 2e 65 78 65 90 00 } //01 00 
		$a_00_8 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4d 69 6e 69 6d 61 6c 5c } //01 00  SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\
		$a_00_9 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4e 65 74 77 6f 72 6b 5c } //00 00  SYSTEM\CurrentControlSet\Control\SafeBoot\Network\
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Nuqsvc_A{
	meta:
		description = "Trojan:Win32/Nuqsvc.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 00 72 00 6c 00 47 00 65 00 74 00 } //4 UrlGet
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 32 00 32 00 2e 00 31 00 38 00 37 00 2e 00 [0-10] 3a 00 36 00 31 00 } //10
		$a_00_2 = {5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 48 00 69 00 64 00 65 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 49 00 63 00 6f 00 6e 00 73 00 5c 00 4e 00 65 00 77 00 53 00 74 00 61 00 72 00 74 00 50 00 61 00 6e 00 65 00 6c 00 } //1 \Explorer\HideDesktopIcons\NewStartPanel
		$a_00_3 = {7b 00 38 00 37 00 31 00 43 00 35 00 33 00 38 00 30 00 2d 00 34 00 32 00 41 00 30 00 2d 00 31 00 30 00 36 00 39 00 2d 00 41 00 32 00 45 00 41 00 2d 00 30 00 38 00 30 00 30 00 32 00 42 00 33 00 30 00 33 00 30 00 39 00 44 00 7d 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 48 00 6f 00 6d 00 65 00 50 00 61 00 67 00 65 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 {871C5380-42A0-1069-A2EA-08002B30309D}\shell\OpenHomePage\Command
		$a_01_4 = {4c 6f 63 6b 49 45 00 } //1
		$a_01_5 = {4c 6f 63 6b 53 74 61 72 74 50 61 67 65 00 } //1 潌正瑓牡側条e
		$a_01_6 = {43 68 61 6e 67 65 48 6f 73 74 73 00 } //1 桃湡敧潈瑳s
		$a_01_7 = {4c 6f 63 6b 44 6e 73 00 } //1 潌正湄s
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=18
 
}
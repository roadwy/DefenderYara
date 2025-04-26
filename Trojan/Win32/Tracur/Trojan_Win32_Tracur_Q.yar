
rule Trojan_Win32_Tracur_Q{
	meta:
		description = "Trojan:Win32/Tracur.Q,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 72 6f 66 69 6c 65 4c 69 73 74 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_2 = {73 65 61 72 63 68 5f 71 75 65 72 79 3d } //1 search_query=
		$a_01_3 = {25 73 3f 71 3d 25 73 26 73 75 3d 25 73 26 25 73 26 7a 3d 25 73 } //1 %s?q=%s&su=%s&%s&z=%s
		$a_01_4 = {26 74 3d 64 69 72 65 63 74 } //1 &t=direct
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 2e 66 73 68 61 72 70 72 6f 6a 5c 50 65 72 73 69 73 74 65 6e 74 48 61 6e 64 6c 65 72 } //1 SOFTWARE\Classes\.fsharproj\PersistentHandler
		$a_01_6 = {75 3d 25 73 26 61 3d 25 73 26 69 3d 25 73 26 73 3d 25 73 } //1 u=%s&a=%s&i=%s&s=%s
		$a_01_7 = {25 73 5c 78 75 6c 63 61 63 68 65 2e 6a 61 72 } //1 %s\xulcache.jar
		$a_01_8 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 2a } //1 Application Data\Mozilla\Firefox\Profiles\*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}
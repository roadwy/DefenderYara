
rule Trojan_Win32_RemcosRAT_Z_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {52 65 6d 63 6f 73 } //1 Remcos
		$a_81_1 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 } //1 %02i:%02i:%02i
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_RemcosRAT_Z_MTB_2{
	meta:
		description = "Trojan:Win32/RemcosRAT.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 65 64 20 66 69 6c 65 } //1 Downloaded file
		$a_81_1 = {47 65 74 44 69 72 65 63 74 4c 69 73 74 65 6e 69 6e 67 50 6f 72 74 } //1 GetDirectListeningPort
		$a_81_2 = {55 70 6c 6f 61 64 65 64 20 66 69 6c 65 } //1 Uploaded file
		$a_81_3 = {72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //1 reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
		$a_81_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1 CreateObject(
		$a_81_5 = {55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73 } //1 User Data\Default\Cookies
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_Win32_RemcosRAT_Z_MTB_3{
	meta:
		description = "Trojan:Win32/RemcosRAT.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 65 6d 63 6f 73 } //1 Remcos
		$a_81_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 22 63 6d 64 } //1 CreateObject("WScript.Shell").Run "cmd
		$a_81_2 = {5c 73 79 73 69 6e 66 6f 2e 74 78 74 } //1 \sysinfo.txt
		$a_81_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion
		$a_81_4 = {72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //1 reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
		$a_81_5 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 } //1 %02i:%02i:%02i
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
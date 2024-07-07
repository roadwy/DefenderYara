
rule TrojanSpy_Win32_Keatep_C{
	meta:
		description = "TrojanSpy:Win32/Keatep.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 6d 69 63 72 6f 75 70 64 61 74 65 } //1 http://microupdate
		$a_00_1 = {53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //1 SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_00_3 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 70 73 65 63 } //1 %s:*:Enabled:ipsec
		$a_02_4 = {8d 85 e4 ea 90 01 02 50 68 3f 00 0f 00 6a 00 8b 0d 90 01 03 00 51 68 01 00 00 80 ff 15 90 01 03 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}
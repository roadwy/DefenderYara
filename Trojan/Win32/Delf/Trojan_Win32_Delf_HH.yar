
rule Trojan_Win32_Delf_HH{
	meta:
		description = "Trojan:Win32/Delf.HH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 ba 90 01 04 8b 45 ec 8b 08 ff 51 38 33 d2 8b 45 ec 8b 08 ff 51 38 ba 90 01 04 8b 45 ec 8b 08 ff 51 38 8d 45 e4 50 8b 45 f8 89 45 d4 c6 45 d8 0b 90 00 } //1
		$a_00_1 = {5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 5d } //1 [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List]
		$a_00_2 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //1 :*:Enabled:
		$a_00_3 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 70 6f 77 65 72 70 6f 69 6e 74 2c 20 2a 2f 2a } //1 application/vnd.ms-powerpoint, */*
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
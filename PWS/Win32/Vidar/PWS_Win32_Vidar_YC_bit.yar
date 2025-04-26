
rule PWS_Win32_Vidar_YC_bit{
	meta:
		description = "PWS:Win32/Vidar.YC!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 8b 4d 08 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 d8 90 09 0c 00 ff 75 ?? 8d 34 1f ff 15 } //1
		$a_01_1 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //1 :Zone.Identifier
		$a_01_2 = {2a 77 61 6c 6c 65 74 2a 2e 64 61 74 } //1 *wallet*.dat
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 69 6e 67 20 53 75 62 73 79 73 74 65 6d 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //1 Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
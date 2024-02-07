
rule Trojan_Win32_Shutdowner_L{
	meta:
		description = "Trojan:Win32/Shutdowner.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 74 74 72 69 62 20 2b 68 20 22 56 69 72 75 73 20 4e 61 6d 65 2e 62 61 74 } //01 00  attrib +h "Virus Name.bat
		$a_01_1 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 66 75 63 6b 65 64 } //01 00  Your system is fucked
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 36 30 20 2d 63 20 22 42 79 65 20 42 79 65 } //01 00  shutdown -s -t 60 -c "Bye Bye
		$a_01_3 = {64 65 6c 20 2f 66 20 2f 71 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 2a } //00 00  del /f /q C:\WINDOWS\system32\*
	condition:
		any of ($a_*)
 
}
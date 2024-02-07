
rule PWS_Win32_Gadu_J{
	meta:
		description = "PWS:Win32/Gadu.J,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 47 20 4e 75 6d 62 65 72 20 3a } //01 00  GG Number :
		$a_01_1 = {5c 47 61 64 75 2d 47 61 64 75 20 31 30 5c } //01 00  \Gadu-Gadu 10\
		$a_01_2 = {41 70 70 6c 65 20 43 6f 6d 70 75 74 65 72 5c 50 72 65 66 65 72 65 6e 63 65 73 5c 6b 65 79 63 68 61 69 6e 2e 70 6c 69 73 74 } //01 00  Apple Computer\Preferences\keychain.plist
		$a_01_3 = {5c 4f 70 65 72 61 5c 4f 70 65 72 61 5c 77 61 6e 64 2e 64 61 74 } //01 00  \Opera\Opera\wand.dat
		$a_01_4 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Google\Chrome\User Data\Default\Login Data
		$a_01_5 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 20 4c 49 4d 49 54 20 31 20 4f 46 46 53 45 54 } //00 00  SELECT * FROM logins LIMIT 1 OFFSET
	condition:
		any of ($a_*)
 
}
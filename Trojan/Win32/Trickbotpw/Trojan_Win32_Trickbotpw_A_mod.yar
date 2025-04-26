
rule Trojan_Win32_Trickbotpw_A_mod{
	meta:
		description = "Trojan:Win32/Trickbotpw.A!mod,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {47 72 61 62 5f 50 61 73 73 77 6f 72 64 73 5f 43 68 72 6f 6d 65 28 30 29 } //1 Grab_Passwords_Chrome(0)
		$a_81_1 = {47 72 61 62 5f 50 61 73 73 77 6f 72 64 73 5f 43 68 72 6f 6d 65 28 29 20 73 75 63 63 65 73 73 } //1 Grab_Passwords_Chrome() success
		$a_81_2 = {47 72 61 62 5f 50 61 73 73 77 6f 72 64 73 5f 43 68 72 6f 6d 65 28 29 3a 20 43 61 6e 27 74 20 6f 70 65 6e 20 64 61 74 61 62 61 73 65 } //1 Grab_Passwords_Chrome(): Can't open database
		$a_81_3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 2e 62 61 6b } //1 \Google\Chrome\User Data\Default\Login Data.bak
		$a_81_4 = {5b 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 5d 3a 3a 4c 6f 61 64 46 69 6c 65 28 22 24 62 69 6e 70 61 74 68 5c 4b 65 65 50 61 73 73 2e 65 78 65 22 29 } //1 [Reflection.Assembly]::LoadFile("$binpath\KeePass.exe")
		$a_81_5 = {57 72 69 74 65 2d 77 61 72 6e 69 6e 67 20 22 55 6e 61 62 6c 65 20 4c 6f 61 64 20 4b 65 65 50 61 73 73 20 42 69 6e 61 72 79 73 22 } //1 Write-warning "Unable Load KeePass Binarys"
		$a_81_6 = {6d 69 6d 69 6b 61 74 7a } //1 mimikatz
		$a_81_7 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 Internet Explorer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
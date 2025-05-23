
rule Worm_Win32_Spetcrum{
	meta:
		description = "Worm:Win32/Spetcrum,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_01_0 = {70 6f 53 65 6e 64 4d 61 69 6c 5f 53 65 6e 64 46 61 69 6c 65 64 } //1 poSendMail_SendFailed
		$a_01_1 = {53 79 73 74 65 6d 54 69 6d 65 54 6f 54 7a 53 70 65 63 69 66 69 63 4c 6f 63 61 6c 54 69 6d 65 } //1 SystemTimeToTzSpecificLocalTime
		$a_01_2 = {53 4d 54 50 48 6f 73 74 56 61 6c 69 64 61 74 69 6f 6e } //1 SMTPHostValidation
		$a_01_3 = {53 53 4c 20 73 65 67 75 72 6f 20 28 31 32 38 20 62 69 74 73 29 } //1 SSL seguro (128 bits)
		$a_01_4 = {70 69 63 4c 6f 63 6b 31 30 } //1 picLock10
		$a_01_5 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 } //1 C:\Arquivos de programas
		$a_01_6 = {41 00 45 00 52 00 4f 00 20 00 42 00 49 00 5a 00 20 00 43 00 4f 00 4d 00 20 00 43 00 4f 00 4f 00 50 00 } //1 AERO BIZ COM COOP
		$a_01_7 = {41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 4d 00 53 00 4e 00 3a 00 } //1 Account MSN:
		$a_01_8 = {52 00 65 00 6d 00 6f 00 74 00 65 00 48 00 6f 00 73 00 74 00 } //1 RemoteHost
		$a_01_9 = {5f 00 3d 00 5f 00 4e 00 65 00 78 00 74 00 50 00 61 00 72 00 74 00 5f 00 30 00 30 00 30 00 5f 00 } //1 _=_NextPart_000_
		$a_01_10 = {7b 00 61 00 2d 00 61 00 67 00 75 00 64 00 6f 00 7d 00 } //1 {a-agudo}
		$a_01_11 = {48 00 54 00 4d 00 4c 00 4d 00 41 00 49 00 4c 00 31 00 5f 00 41 00 44 00 44 00 52 00 4d 00 41 00 49 00 4c 00 } //1 HTMLMAIL1_ADDRMAIL
		$a_01_12 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4d 00 69 00 6c 00 6c 00 65 00 6e 00 69 00 75 00 6d 00 } //1 Windows Millenium
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=10
 
}
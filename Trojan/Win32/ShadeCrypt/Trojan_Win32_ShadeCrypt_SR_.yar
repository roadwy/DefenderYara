
rule Trojan_Win32_ShadeCrypt_SR_{
	meta:
		description = "Trojan:Win32/ShadeCrypt.SR!!Shade.gen!SD,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_81_0 = {70 77 64 63 68 65 63 6b 2e 76 62 73 } //1 pwdcheck.vbs
		$a_81_1 = {70 6f 73 74 73 65 74 75 70 2e 63 6d 64 } //1 postsetup.cmd
		$a_81_2 = {50 6f 73 74 63 6f 6e 6e 65 63 74 2e 78 6d 6c } //1 Postconnect.xml
		$a_81_3 = {72 65 67 69 6e 69 2e 74 78 74 } //1 regini.txt
		$a_81_4 = {72 65 67 73 65 74 2e 76 62 73 63 } //1 regset.vbsc
		$a_81_5 = {72 65 6c 65 61 73 65 20 6e 6f 74 65 73 2e 64 6f 63 78 } //1 release notes.docx
		$a_81_6 = {2d 2d 69 67 6e 6f 72 65 2d 6d 69 73 73 69 6e 67 2d 74 6f 72 72 63 } //1 --ignore-missing-torrc
		$a_81_7 = {67 72 6f 6f 76 65 2e 6e 65 74 5c 67 72 6f 6f 76 65 66 6f 72 6d 73 33 5c 66 6f 72 6d 73 73 74 79 6c 65 73 5c 62 72 69 67 68 74 6f 72 61 6e 67 65 5c 62 61 63 6b 67 72 6f 75 6e 64 2e 67 69 66 } //1 groove.net\grooveforms3\formsstyles\brightorange\background.gif
		$a_81_8 = {5c 44 61 74 61 41 72 63 68 69 76 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 63 72 79 70 74 6f 5c 72 73 61 5c 6d 61 63 68 69 6e 65 6b 65 79 73 5c } //1 \DataArchive\microsoft\crypto\rsa\machinekeys\
		$a_81_9 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 \SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
		$a_81_10 = {5c 53 61 6d 70 6c 65 73 5c 44 75 6d 70 61 32 32 32 2e 65 78 65 } //1 \Samples\Dumpa222.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=10
 
}
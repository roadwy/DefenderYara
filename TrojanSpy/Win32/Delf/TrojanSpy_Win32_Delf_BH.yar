
rule TrojanSpy_Win32_Delf_BH{
	meta:
		description = "TrojanSpy:Win32/Delf.BH,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {69 6e 70 75 74 5f 6d 61 69 6c 5f 70 77 64 32 } //1 input_mail_pwd2
		$a_01_1 = {4c 4f 43 41 2d 57 45 42 20 57 45 42 4d 41 49 4c } //1 LOCA-WEB WEBMAIL
		$a_01_2 = {70 63 5f 6c 6f 67 69 6e } //1 pc_login
		$a_01_3 = {70 63 5f 70 61 73 73 77 6f 72 64 } //1 pc_password
		$a_01_4 = {68 70 2d 75 73 65 72 6e 61 6d 65 2d 69 6e 70 } //1 hp-username-inp
		$a_01_5 = {68 70 2d 70 61 73 73 77 6f 72 64 2d 69 6e 70 } //1 hp-password-inp
		$a_01_6 = {6d 61 69 6c 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //1 mail.terra.com.br
		$a_01_7 = {69 67 65 6d 70 72 65 73 61 73 2e 63 6f 6d 2e 62 72 } //1 igempresas.com.br
		$a_01_8 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 6e 6f 2d 69 70 2e 63 6f 6d 2f 6c 6f 67 69 6e 2f 3f 6c 6f 67 6f 75 74 3d 31 } //1 https://www.no-ip.com/login/?logout=1
		$a_01_9 = {50 72 6f 67 72 65 73 73 43 68 61 6e 67 65 3a 20 } //1 ProgressChange: 
		$a_01_10 = {43 6f 6d 6d 61 6e 64 53 74 61 74 65 43 68 61 6e 67 65 3a 20 43 4f 4d 4d 41 4e 44 3a } //1 CommandStateChange: COMMAND:
		$a_01_11 = {44 6f 77 6e 6c 6f 61 64 20 42 65 67 69 6e } //1 Download Begin
		$a_01_12 = {44 6f 77 6e 6c 6f 61 64 20 43 6f 6d 70 6c 65 74 65 } //1 Download Complete
		$a_01_13 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}
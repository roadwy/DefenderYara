
rule Trojan_Linux_HideUserAccounts_A{
	meta:
		description = "Trojan:Linux/HideUserAccounts.A,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 20 00 73 00 65 00 74 00 } //10 gsettings set
		$a_00_1 = {6f 00 72 00 67 00 2e 00 67 00 6e 00 6f 00 6d 00 65 00 2e 00 6c 00 6f 00 67 00 69 00 6e 00 2d 00 73 00 63 00 72 00 65 00 65 00 6e 00 } //10 org.gnome.login-screen
		$a_00_2 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 2d 00 75 00 73 00 65 00 72 00 2d 00 6c 00 69 00 73 00 74 00 } //10 disable-user-list
		$a_00_3 = {74 00 72 00 75 00 65 00 } //10 true
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}
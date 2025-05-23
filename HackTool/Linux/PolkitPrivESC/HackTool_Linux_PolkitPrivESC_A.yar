
rule HackTool_Linux_PolkitPrivESC_A{
	meta:
		description = "HackTool:Linux/PolkitPrivESC.A,SIGNATURE_TYPE_CMDHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_00_0 = {64 00 62 00 75 00 73 00 2d 00 73 00 65 00 6e 00 64 00 20 00 2d 00 2d 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //2 dbus-send --system
		$a_00_1 = {2d 00 2d 00 74 00 79 00 70 00 65 00 3d 00 6d 00 65 00 74 00 68 00 6f 00 64 00 5f 00 63 00 61 00 6c 00 6c 00 } //2 --type=method_call
		$a_00_2 = {6f 00 72 00 67 00 2e 00 66 00 72 00 65 00 65 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 } //2 org.freedesktop.Accounts
		$a_00_3 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 55 00 73 00 65 00 72 00 } //2 .CreateUser
		$a_00_4 = {55 00 73 00 65 00 72 00 2e 00 53 00 65 00 74 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //2 User.SetPassword
		$a_00_5 = {73 00 6c 00 65 00 65 00 70 00 } //1 sleep
		$a_00_6 = {6b 00 69 00 6c 00 6c 00 20 00 24 00 } //1 kill $
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}

rule VirTool_Win32_Kekeo_B{
	meta:
		description = "VirTool:Win32/Kekeo.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {62 61 73 65 36 34 28 74 69 63 6b 65 74 2e 6b 69 72 62 69 29 } //base64(ticket.kirbi)  1
		$a_80_1 = {6b 72 62 74 67 74 2f 7b 30 7d } //krbtgt/{0}  1
		$a_80_2 = {6b 72 62 74 67 74 2f 2e 2a } //krbtgt/.*  1
		$a_80_3 = {2f 64 6f 6d 61 69 6e 3a } ///domain:  1
		$a_80_4 = {2f 69 6d 70 65 72 73 6f 6e 61 74 65 75 73 65 72 } ///impersonateuser  1
		$a_80_5 = {2f 6b 72 62 6b 65 79 } ///krbkey  1
		$a_80_6 = {28 21 73 61 6d 41 63 63 6f 75 6e 74 4e 61 6d 65 3d 6b 72 62 74 67 74 29 28 21 28 55 73 65 72 41 63 63 6f 75 6e 74 43 6f 6e 74 72 6f 6c 3a } //(!samAccountName=krbtgt)(!(UserAccountControl:  1
		$a_80_7 = {4b 72 62 43 72 65 64 00 } //KrbCred  1
		$a_80_8 = {62 61 73 65 36 34 28 7b 30 7d 2e 6b 69 72 62 69 29 } //base64({0}.kirbi)  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=7
 
}

rule Trojan_Win32_VBInject_VA_MSR{
	meta:
		description = "Trojan:Win32/VBInject.VA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 64 66 76 78 76 78 76 76 78 63 76 76 76 } //sdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfvxvxvvxcvvv  01 00 
		$a_80_1 = {71 71 71 71 71 71 71 71 71 71 71 71 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 } //qqqqqqqqqqqqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  01 00 
		$a_80_2 = {72 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 73 77 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 } //rfffffffffffffffffffffffffffffffffffffswrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr  01 00 
		$a_80_3 = {66 73 64 66 66 66 66 66 66 72 74 65 72 77 72 65 72 77 } //fsdffffffrterwrerw  01 00 
		$a_80_4 = {66 72 6d 4c 6f 67 69 6e } //frmLogin  01 00 
		$a_80_5 = {66 72 6d 53 70 6c 61 73 68 } //frmSplash  01 00 
		$a_80_6 = {66 72 6d 54 69 70 } //frmTip  01 00 
		$a_80_7 = {66 72 6d 42 72 6f 77 73 65 72 } //frmBrowser  01 00 
		$a_80_8 = {66 72 6d 4f 70 74 69 6f 6e 73 } //frmOptions  01 00 
		$a_80_9 = {66 72 6d 4f 44 42 43 4c 6f 67 6f 6e } //frmODBCLogon  01 00 
		$a_80_10 = {66 72 6d 4f 70 74 69 6f 6e 73 31 } //frmOptions1  01 00 
		$a_80_11 = {66 72 6d 4c 6f 67 69 6e 31 } //frmLogin1  00 00 
	condition:
		any of ($a_*)
 
}
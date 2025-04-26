
rule Trojan_Win32_SuspStartupInstall_ZPB{
	meta:
		description = "Trojan:Win32/SuspStartupInstall.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } //1 schtasks
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 /create
		$a_00_2 = {20 00 2f 00 74 00 6e 00 20 00 } //1  /tn 
		$a_00_3 = {2f 00 73 00 63 00 20 00 6f 00 6e 00 73 00 74 00 61 00 72 00 74 00 } //1 /sc onstart
		$a_00_4 = {2f 00 72 00 75 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //1 /ru system
		$a_00_5 = {20 00 2f 00 74 00 72 00 20 00 } //1  /tr 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
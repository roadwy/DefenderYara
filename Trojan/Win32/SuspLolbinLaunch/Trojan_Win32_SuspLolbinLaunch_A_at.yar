
rule Trojan_Win32_SuspLolbinLaunch_A_at{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.A!at,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 61 00 74 00 2e 00 65 00 78 00 65 00 } //1 \at.exe
		$a_00_1 = {20 00 61 00 74 00 20 00 } //1  at 
		$a_00_2 = {2f 00 69 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 76 00 65 00 } //1 /interactive
		$a_00_3 = {2f 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 20 00 5c 00 5c 00 } //1 /computername \\
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}
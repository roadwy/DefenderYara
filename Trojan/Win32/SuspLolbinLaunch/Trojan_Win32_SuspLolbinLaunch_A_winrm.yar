
rule Trojan_Win32_SuspLolbinLaunch_A_winrm{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.A!winrm,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 69 00 6e 00 72 00 6d 00 } //2 winrm
		$a_02_1 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 [0-f0] 5c 00 5c 00 } //1
		$a_02_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 [0-f0] 68 00 74 00 74 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
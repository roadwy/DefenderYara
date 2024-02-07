
rule Trojan_Win32_MpTamperBlockSetFirewall_D{
	meta:
		description = "Trojan:Win32/MpTamperBlockSetFirewall.D,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 76 00 31 00 2e 00 30 00 5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //02 00  \system32\windowspowershell\v1.0\powershell.exe
		$a_00_1 = {73 00 65 00 74 00 2d 00 6e 00 65 00 74 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 72 00 75 00 6c 00 65 00 20 00 } //02 00  set-netfirewallrule 
		$a_02_2 = {2d 00 73 00 65 00 72 00 90 02 0f 73 00 65 00 6e 00 73 00 65 00 90 00 } //01 00 
		$a_02_3 = {2d 00 61 00 63 00 90 02 0f 62 00 90 00 } //01 00 
		$a_02_4 = {2d 00 61 00 63 00 90 02 0f 30 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
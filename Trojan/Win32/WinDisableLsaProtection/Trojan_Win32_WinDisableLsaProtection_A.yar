
rule Trojan_Win32_WinDisableLsaProtection_A{
	meta:
		description = "Trojan:Win32/WinDisableLsaProtection.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {20 00 61 00 64 00 64 00 20 00 } //1  add 
		$a_00_1 = {5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4c 00 53 00 41 00 20 00 } //1 \SYSTEM\CurrentControlSet\Control\LSA 
		$a_00_2 = {2f 00 76 00 20 00 52 00 75 00 6e 00 41 00 73 00 50 00 50 00 4c 00 } //1 /v RunAsPPL
		$a_00_3 = {2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 } //1 /t REG_DWORD
		$a_00_4 = {2f 00 64 00 20 00 30 00 } //1 /d 0
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
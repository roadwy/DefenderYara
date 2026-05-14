
rule Trojan_Win32_ResAdmin_Z_MTB{
	meta:
		description = "Trojan:Win32/ResAdmin.Z!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 } //1 reg add
		$a_00_1 = {48 00 4b 00 4c 00 4d 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4c 00 73 00 61 00 } //1 HKLM\SYSTEM\CurrentControlSet\Control\Lsa
		$a_00_2 = {2f 00 76 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 73 00 74 00 72 00 69 00 63 00 74 00 65 00 64 00 41 00 64 00 6d 00 69 00 6e 00 } //1 /v DisableRestrictedAdmin
		$a_00_3 = {2f 00 64 00 20 00 30 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 } //1 /d 0 /t REG_DWORD
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
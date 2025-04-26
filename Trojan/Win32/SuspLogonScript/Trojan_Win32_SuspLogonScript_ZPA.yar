
rule Trojan_Win32_SuspLogonScript_ZPA{
	meta:
		description = "Trojan:Win32/SuspLogonScript.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {20 00 61 00 64 00 64 00 20 00 } //1  add 
		$a_00_1 = {2f 00 76 00 20 00 55 00 73 00 65 00 72 00 49 00 6e 00 69 00 74 00 4d 00 70 00 72 00 4c 00 6f 00 67 00 6f 00 6e 00 53 00 63 00 72 00 69 00 70 00 74 00 } //1 /v UserInitMprLogonScript
		$a_00_2 = {2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 } //1 /t REG_SZ
		$a_00_3 = {20 00 2f 00 64 00 } //1  /d
		$a_00_4 = {5c 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 } //1 \Environment
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
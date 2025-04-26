
rule Trojan_Win32_AppPathBypass_ZPA{
	meta:
		description = "Trojan:Win32/AppPathBypass.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 41 00 70 00 70 00 50 00 61 00 74 00 68 00 42 00 79 00 70 00 61 00 73 00 73 00 } //1 Invoke-AppPathBypass
		$a_00_1 = {20 00 2d 00 50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 } //1  -Payload
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
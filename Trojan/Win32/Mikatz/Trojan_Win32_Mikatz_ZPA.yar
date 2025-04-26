
rule Trojan_Win32_Mikatz_ZPA{
	meta:
		description = "Trojan:Win32/Mikatz.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 } //1 sekurlsa
		$a_00_1 = {3a 00 3a 00 6d 00 69 00 6e 00 69 00 64 00 75 00 6d 00 70 00 } //1 ::minidump
		$a_00_2 = {3a 00 3a 00 6c 00 6f 00 67 00 6f 00 6e 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 ::logonpassword
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}
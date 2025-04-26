
rule Trojan_Win32_RemoteInjection_ZPA{
	meta:
		description = "Trojan:Win32/RemoteInjection.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 6c 00 73 00 61 00 } //1 lsadump::lsa
		$a_00_1 = {20 00 2f 00 69 00 6e 00 6a 00 65 00 63 00 74 00 20 00 } //1  /inject 
		$a_00_2 = {20 00 2f 00 69 00 64 00 3a 00 } //1  /id:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
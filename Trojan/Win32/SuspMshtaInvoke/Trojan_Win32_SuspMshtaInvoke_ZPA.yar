
rule Trojan_Win32_SuspMshtaInvoke_ZPA{
	meta:
		description = "Trojan:Win32/SuspMshtaInvoke.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //1 mshta.exe
		$a_00_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 } //1 javascript:
		$a_00_2 = {47 00 65 00 74 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //1 GetObject(
		$a_00_3 = {73 00 63 00 72 00 69 00 70 00 74 00 3a 00 } //1 script:
		$a_00_4 = {2e 00 45 00 78 00 65 00 63 00 28 00 29 00 } //1 .Exec()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
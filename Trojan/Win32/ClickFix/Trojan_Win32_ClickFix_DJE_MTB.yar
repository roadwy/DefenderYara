
rule Trojan_Win32_ClickFix_DJE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DJE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 00 6f 00 72 00 66 00 69 00 6c 00 65 00 73 00 20 00 2f 00 70 00 } //1 forfiles /p
		$a_00_1 = {2f 00 6d 00 20 00 6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 } //1 /m notepad.exe /c
		$a_00_2 = {73 00 74 00 61 00 72 00 74 00 20 00 6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1 start mshta http://
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
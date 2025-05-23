
rule Trojan_Win32_ClickFix_AL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,33 00 33 00 07 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //10 wscript.shell
		$a_00_1 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_2 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
		$a_00_3 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00 } //10 vbscript:Execute(
		$a_00_4 = {73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //10 start-process
		$a_00_5 = {20 00 69 00 72 00 6d 00 } //1  irm
		$a_00_6 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 } //1 invoke-webrequest
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=51
 
}
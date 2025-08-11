
rule Trojan_Win32_ClickFix_DEL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffa1 00 ffffffa1 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_02_1 = {53 00 74 00 61 00 72 00 74 00 [0-04] 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //50
		$a_00_2 = {77 00 77 00 77 00 2e 00 7a 00 6f 00 75 00 74 00 75 00 62 00 65 00 2e 00 63 00 6f 00 6d 00 } //10 www.zoutube.com
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_02_1  & 1)*50+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=161
 
}
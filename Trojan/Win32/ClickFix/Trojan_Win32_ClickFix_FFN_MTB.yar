
rule Trojan_Win32_ClickFix_FFN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {7c 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 | powershell
		$a_00_1 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_3 = {59 00 6f 00 75 00 72 00 20 00 57 00 6f 00 72 00 6b 00 20 00 53 00 74 00 61 00 72 00 74 00 73 00 20 00 48 00 65 00 72 00 65 00 } //1 Your Work Starts Here
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}

rule Trojan_Win32_ClickFix_BBF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {5b 00 73 00 74 00 72 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 43 00 6f 00 6e 00 63 00 61 00 74 00 28 00 28 00 } //1 [string]::Concat((
		$a_00_2 = {2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 21 00 27 00 } //1 .replace('!'
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
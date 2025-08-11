
rule Trojan_Win32_ClickFix_BBU_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {2d 00 6a 00 6f 00 69 00 6e 00 28 00 5b 00 63 00 68 00 61 00 72 00 5b 00 5d 00 5d 00 } //1 -join([char[]]
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
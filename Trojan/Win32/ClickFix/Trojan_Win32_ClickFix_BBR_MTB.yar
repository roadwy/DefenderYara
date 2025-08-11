
rule Trojan_Win32_ClickFix_BBR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {29 00 7c 00 25 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 7d 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 27 00 27 00 29 00 } //1 )|%{[char]$_})-join'')
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_2 = {29 00 7c 00 25 00 7b 00 26 00 24 00 5f 00 20 00 28 00 } //1 )|%{&$_ (
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}

rule Trojan_Win32_ClickFix_ZMP_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZMP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 00 6f 00 72 00 45 00 61 00 63 00 68 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 7b 00 5b 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 54 00 6f 00 42 00 79 00 74 00 65 00 28 00 24 00 } //1 ForEach-Object {[Convert]::ToByte($
		$a_00_1 = {2e 00 53 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 } //1 .Substring
		$a_00_2 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //1 .GetString(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
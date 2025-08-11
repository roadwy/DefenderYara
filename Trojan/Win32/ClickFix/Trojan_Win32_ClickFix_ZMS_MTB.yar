
rule Trojan_Win32_ClickFix_ZMS_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZMS!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 74 00 2e 00 48 00 74 00 74 00 70 00 2e 00 48 00 74 00 74 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5d 00 3a 00 3a 00 6e 00 65 00 77 00 } //1 Net.Http.HttpClient]::new
		$a_00_1 = {28 00 5b 00 53 00 63 00 72 00 69 00 70 00 74 00 42 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 24 00 } //1 ([ScriptBlock]::Create($
		$a_00_2 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 41 00 73 00 79 00 6e 00 63 00 28 00 } //1 .GetStringAsync(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
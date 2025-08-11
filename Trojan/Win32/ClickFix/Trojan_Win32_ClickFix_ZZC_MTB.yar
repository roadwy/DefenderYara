
rule Trojan_Win32_ClickFix_ZZC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZZC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 20 00 24 00 } //1 iex $
		$a_00_1 = {5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 [System.Convert]::FromBase64String($
		$a_00_2 = {43 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 20 00 61 00 63 00 63 00 65 00 73 00 73 00 } //1 Confirm access
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
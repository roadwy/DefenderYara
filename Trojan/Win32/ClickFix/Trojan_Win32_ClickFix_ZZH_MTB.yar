
rule Trojan_Win32_ClickFix_ZZH_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZZH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5b 00 49 00 4f 00 2e 00 46 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 52 00 65 00 61 00 64 00 41 00 6c 00 6c 00 42 00 79 00 74 00 65 00 73 00 28 00 24 00 } //1 [IO.File]::ReadAllBytes($
		$a_00_1 = {46 00 6f 00 72 00 45 00 61 00 63 00 68 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 7b 00 20 00 24 00 5f 00 2e 00 54 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 ForEach-Object { $_.ToString
		$a_00_2 = {2d 00 6a 00 6f 00 69 00 6e 00 } //1 -join
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
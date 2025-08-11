
rule Trojan_Win32_ClickFix_EEK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 3b 00 69 00 65 00 78 00 20 00 24 00 } //1 New-Object Net.WebClient;iex $
		$a_00_1 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 .DownloadString($
		$a_00_2 = {24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //1 $env:TEMP
		$a_00_3 = {2d 00 6a 00 6f 00 69 00 6e 00 20 00 27 00 27 00 3b 00 24 00 } //1 -join '';$
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
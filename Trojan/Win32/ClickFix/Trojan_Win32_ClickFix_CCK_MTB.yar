
rule Trojan_Win32_ClickFix_CCK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 24 00 } //1 .DownloadFile($
		$a_00_1 = {2e 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00 2e 00 41 00 64 00 64 00 28 00 } //1 .Headers.Add(
		$a_00_2 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
		$a_00_3 = {29 00 3b 00 26 00 24 00 } //1 );&$
		$a_00_4 = {24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //1 $env:TEMP
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}

rule Trojan_Win32_ClickFix_FFH_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
		$a_00_1 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 .DownloadString
		$a_00_2 = {2e 00 74 00 78 00 74 00 27 00 29 00 20 00 7c 00 20 00 49 00 45 00 58 00 } //1 .txt') | IEX
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
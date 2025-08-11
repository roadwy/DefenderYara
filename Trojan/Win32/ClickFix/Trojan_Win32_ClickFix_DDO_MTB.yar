
rule Trojan_Win32_ClickFix_DDO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 2e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 5d 00 3a 00 3a 00 4d 00 61 00 69 00 6e 00 28 00 29 00 } //1 [ProcessInjector.Program]::Main()
		$a_00_1 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
		$a_00_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 DownloadString
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
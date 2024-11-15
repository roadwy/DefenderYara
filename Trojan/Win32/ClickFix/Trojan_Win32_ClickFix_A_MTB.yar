
rule Trojan_Win32_ClickFix_A_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 24 00 } //1 -command $
		$a_00_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 2d 00 55 00 72 00 69 00 20 00 24 00 } //1 Invoke-WebRequest -Uri $
		$a_00_3 = {2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 3b 00 20 00 69 00 65 00 78 00 20 00 24 00 } //1 .Content; iex $
		$a_00_4 = {5c 00 31 00 } //1 \1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
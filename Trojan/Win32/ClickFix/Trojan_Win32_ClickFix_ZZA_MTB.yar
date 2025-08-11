
rule Trojan_Win32_ClickFix_ZZA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZZA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 28 00 5b 00 53 00 63 00 72 00 69 00 70 00 74 00 42 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 24 00 5f 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 Invoke-Command ([ScriptBlock]::Create($_.Content
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_02_2 = {68 00 74 00 74 00 70 00 3a 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 2f 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
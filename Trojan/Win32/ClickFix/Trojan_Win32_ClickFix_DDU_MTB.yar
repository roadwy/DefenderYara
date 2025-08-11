
rule Trojan_Win32_ClickFix_DDU_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {5b 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 5d 00 3a 00 3a 00 53 00 65 00 74 00 54 00 65 00 78 00 74 00 28 00 5b 00 44 00 61 00 74 00 65 00 54 00 69 00 6d 00 65 00 5d 00 3a 00 3a 00 55 00 74 00 63 00 4e 00 6f 00 77 00 2e 00 54 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 [Windows.Clipboard]::SetText([DateTime]::UtcNow.ToString
		$a_00_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
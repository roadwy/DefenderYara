
rule Trojan_Win32_ClickFix_FFO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3b 00 77 00 68 00 69 00 6c 00 65 00 20 00 28 00 24 00 74 00 72 00 75 00 65 00 29 00 7b 00 24 00 } //1 ;while ($true){$
		$a_00_1 = {49 00 52 00 4d 00 20 00 } //1 IRM 
		$a_00_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_3 = {48 00 65 00 61 00 64 00 65 00 72 00 73 00 20 00 40 00 } //1 Headers @
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
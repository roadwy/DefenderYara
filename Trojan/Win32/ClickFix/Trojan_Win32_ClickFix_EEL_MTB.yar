
rule Trojan_Win32_ClickFix_EEL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 00 73 00 65 00 6e 00 64 00 28 00 29 00 3b 00 69 00 65 00 78 00 28 00 5b 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 54 00 46 00 38 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 .send();iex([Text.Encoding]::UTF8.GetString($
		$a_02_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-20] 3b 00 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
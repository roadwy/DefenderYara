
rule Trojan_Win32_ClickFix_EEB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00 20 00 40 00 7b 00 52 00 65 00 66 00 65 00 72 00 65 00 72 00 } //1 -Headers @{Referer
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //1 $env:TEMP
		$a_00_2 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 Start-Process
		$a_00_3 = {2d 00 46 00 69 00 6c 00 65 00 50 00 61 00 74 00 68 00 20 00 24 00 } //1 -FilePath $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
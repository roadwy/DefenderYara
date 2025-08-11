
rule Trojan_Win32_ClickFix_BBJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2b 00 28 00 47 00 65 00 74 00 2d 00 52 00 61 00 6e 00 64 00 6f 00 6d 00 29 00 2b 00 } //1 +(Get-Random)+
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //1 $env:TEMP
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
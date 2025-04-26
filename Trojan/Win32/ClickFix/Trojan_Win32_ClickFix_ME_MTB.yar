
rule Trojan_Win32_ClickFix_ME_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ME!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 77 00 20 00 31 00 20 00 26 00 20 00 5c 00 57 00 } //1 PowerShell.exe -w 1 & \W
		$a_00_1 = {6d 00 2a 00 68 00 74 00 2a 00 65 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //2 m*ht*e https://
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2) >=3
 
}
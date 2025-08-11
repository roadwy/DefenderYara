
rule Trojan_Win32_ClickFix_CCN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 } //10 msiexec
		$a_00_1 = {2e 00 6d 00 73 00 69 00 } //10 .msi
		$a_00_2 = {2f 00 71 00 } //1 /q
		$a_00_3 = {2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 } //1 /package
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}
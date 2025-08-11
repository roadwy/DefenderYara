
rule Trojan_Win32_ClickFix_DCM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 2f 00 63 00 } //100 cmd /min /c
		$a_00_1 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 } //1 -UseBasicParsing
		$a_00_2 = {2d 00 75 00 73 00 65 00 62 00 } //1 -useb
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=101
 
}
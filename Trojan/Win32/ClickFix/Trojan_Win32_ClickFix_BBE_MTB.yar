
rule Trojan_Win32_ClickFix_BBE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {2e 00 53 00 70 00 6c 00 69 00 74 00 28 00 27 00 2c 00 27 00 29 00 3b 00 24 00 } //1 .Split(',');$
		$a_00_2 = {27 00 2b 00 27 00 } //1 '+'
		$a_00_3 = {43 00 4d 00 57 00 5f 00 53 00 69 00 67 00 6e 00 61 00 6c 00 69 00 6e 00 67 00 5f 00 54 00 78 00 } //-100 CMW_Signaling_Tx
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-100) >=3
 
}
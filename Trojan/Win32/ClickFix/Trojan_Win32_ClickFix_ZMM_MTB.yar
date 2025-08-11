
rule Trojan_Win32_ClickFix_ZMM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZMM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,69 00 69 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 20 00 6c 00 6f 00 67 00 20 00 6e 00 6f 00 74 00 69 00 63 00 65 00 } //100 Completed without log notice
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //5 powershell
		$a_00_2 = {6d 00 73 00 68 00 74 00 61 00 } //5 mshta
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5) >=105
 
}
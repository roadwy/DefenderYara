
rule Trojan_Win32_ClickFix_DCA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2e 00 72 00 65 00 50 00 6c 00 41 00 63 00 65 00 28 00 } //10 .rePlAce(
		$a_00_2 = {2e 00 74 00 6f 00 73 00 54 00 72 00 49 00 4e 00 67 00 28 00 29 00 } //10 .tosTrINg()
		$a_00_3 = {2d 00 4a 00 6f 00 69 00 4e 00 } //1 -JoiN
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}
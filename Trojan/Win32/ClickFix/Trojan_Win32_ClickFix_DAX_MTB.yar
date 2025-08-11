
rule Trojan_Win32_ClickFix_DAX_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DAX!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,7d 00 7d 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_02_1 = {73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-02] 24 00 } //10
		$a_00_2 = {3d 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 } //10 =$env:temp
		$a_00_3 = {2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 } //5 -outfile
	condition:
		((#a_00_0  & 1)*100+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*5) >=125
 
}
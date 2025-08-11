
rule Trojan_Win32_ClickFix_DEB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {26 00 28 00 67 00 63 00 4d 00 20 00 2a 00 77 00 72 00 29 00 } //10 &(gcM *wr)
		$a_00_2 = {7c 00 26 00 28 00 67 00 63 00 6d 00 20 00 69 00 2a 00 78 00 29 00 } //10 |&(gcm i*x)
		$a_00_3 = {7c 00 69 00 65 00 78 00 } //10 |iex
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=120
 
}
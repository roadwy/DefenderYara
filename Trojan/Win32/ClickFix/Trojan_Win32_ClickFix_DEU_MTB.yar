
rule Trojan_Win32_ClickFix_DEU_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {3d 00 27 00 69 00 65 00 78 00 27 00 3b 00 26 00 } //10 ='iex';&
		$a_00_2 = {3d 00 27 00 69 00 65 00 78 00 27 00 3b 00 20 00 26 00 } //10 ='iex'; &
		$a_00_3 = {2e 00 63 00 6f 00 6d 00 2f 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 } //1 .com/all.php
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=111
 
}
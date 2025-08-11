
rule Trojan_Win32_ClickFix_DDA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 48 00 49 00 44 00 20 00 2d 00 63 00 20 00 24 00 } //10 -Window HID -c $
		$a_00_2 = {2e 00 70 00 68 00 70 00 3f 00 61 00 6e 00 3d 00 31 00 27 00 3b 00 } //10 .php?an=1';
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=120
 
}

rule Trojan_Win32_ClickFix_DBY_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBY!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {5b 00 73 00 74 00 72 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 6a 00 6f 00 69 00 6e 00 28 00 } //10 [string]::join(
		$a_00_2 = {2d 00 77 00 20 00 68 00 20 00 2d 00 4e 00 6f 00 50 00 20 00 2d 00 63 00 } //1 -w h -NoP -c
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=111
 
}
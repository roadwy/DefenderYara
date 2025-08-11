
rule Trojan_Win32_ClickFix_DFE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DFE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {3d 00 24 00 65 00 6e 00 76 00 3a 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 2b 00 } //10 =$env:APPDATA+
		$a_00_2 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 24 00 } //10 .DownloadFile($
		$a_00_3 = {24 00 61 00 2b 00 24 00 62 00 2b 00 24 00 63 00 2b 00 24 00 64 00 } //10 $a+$b+$c+$d
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}
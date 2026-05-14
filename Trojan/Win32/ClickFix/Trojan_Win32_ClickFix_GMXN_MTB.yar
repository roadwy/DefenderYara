
rule Trojan_Win32_ClickFix_GMXN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GMXN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {65 00 6e 00 76 00 3a 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 76 00 2e 00 70 00 72 00 6f 00 6a 00 } //1 env:programdata\v.proj
		$a_00_2 = {6d 00 73 00 62 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //1 msbuild.exe
		$a_00_3 = {32 00 66 00 61 00 2d 00 62 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 2fa-bns.com
		$a_00_4 = {69 00 77 00 72 00 } //1 iwr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
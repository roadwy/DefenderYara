
rule Trojan_Win32_ClickFix_AH_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff9a 01 ffffff9a 01 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {63 00 75 00 72 00 6c 00 } //100 curl
		$a_00_2 = {2d 00 6a 00 6f 00 69 00 6e 00 } //100 -join
		$a_00_3 = {5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 24 00 } //100 [char]($
		$a_00_4 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //10 invoke-expression
		$a_00_5 = {69 00 65 00 78 00 } //10 iex
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10) >=410
 
}
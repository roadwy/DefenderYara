
rule Trojan_Win32_ClickFix_FFM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 05 00 00 "
		
	strings :
		$a_00_0 = {57 00 2a 00 73 00 5c 00 53 00 2a 00 32 00 } //100 W*s\S*2
		$a_00_1 = {20 00 69 00 65 00 78 00 } //1  iex
		$a_00_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 Invoke-Expression
		$a_00_3 = {7c 00 69 00 65 00 78 00 } //1 |iex
		$a_00_4 = {6d 00 73 00 65 00 64 00 67 00 65 00 77 00 65 00 62 00 76 00 69 00 65 00 77 00 32 00 2e 00 65 00 78 00 65 00 } //-100 msedgewebview2.exe
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*-100) >=101
 
}
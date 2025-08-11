
rule Trojan_Win32_ClickFix_FFQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 05 00 00 "
		
	strings :
		$a_00_0 = {23 00 20 00 56 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //100 # Verification
		$a_00_1 = {7c 00 20 00 69 00 65 00 78 00 } //1 | iex
		$a_00_2 = {7c 00 20 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 | invoke-expression
		$a_00_3 = {3b 00 69 00 65 00 78 00 28 00 24 00 } //1 ;iex($
		$a_00_4 = {3b 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 28 00 24 00 } //1 ;invoke-expression($
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=101
 
}
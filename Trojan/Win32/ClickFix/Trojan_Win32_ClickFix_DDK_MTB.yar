
rule Trojan_Win32_ClickFix_DDK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_00_0 = {7c 00 25 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 7d 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 27 00 } //100 |%{[char]$_})-join'
		$a_00_1 = {69 00 65 00 78 00 20 00 24 00 } //1 iex $
		$a_00_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 } //1 invoke-expresssion $
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=101
 
}

rule Trojan_Win32_ClickFix_DDR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {7c 00 69 00 65 00 78 00 20 00 23 00 50 00 61 00 73 00 73 00 20 00 56 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 41 00 63 00 63 00 65 00 73 00 } //1 |iex #Pass Verification Acces
		$a_00_1 = {7c 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 23 00 50 00 61 00 73 00 73 00 20 00 56 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 41 00 63 00 63 00 65 00 73 00 73 00 } //1 |invoke-expression #Pass Verification Access
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
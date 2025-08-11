
rule Trojan_Win32_ClickFix_HE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffca 00 ffffffca 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 invoke-expression $script
		$a_00_2 = {69 00 65 00 78 00 20 00 24 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 iex $script
		$a_00_3 = {24 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 3d 00 20 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 52 00 65 00 73 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 2d 00 55 00 72 00 69 00 } //200 $script = Invoke-RestMethod -Uri
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*200) >=202
 
}
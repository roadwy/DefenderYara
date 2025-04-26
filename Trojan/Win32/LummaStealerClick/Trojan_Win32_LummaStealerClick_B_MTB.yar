
rule Trojan_Win32_LummaStealerClick_B_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //1 $env:computername
		$a_00_2 = {69 00 65 00 78 00 20 00 24 00 } //1 iex $
		$a_00_3 = {75 00 73 00 65 00 72 00 61 00 67 00 65 00 6e 00 74 00 } //1 useragent
		$a_00_4 = {2e 00 70 00 68 00 70 00 3f 00 63 00 6f 00 6d 00 70 00 6e 00 61 00 6d 00 65 00 } //1 .php?compname
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
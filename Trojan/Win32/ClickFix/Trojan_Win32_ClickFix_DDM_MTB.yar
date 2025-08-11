
rule Trojan_Win32_ClickFix_DDM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 } //10 -UseBasicParsing
		$a_00_2 = {2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //10 .Content
		$a_00_3 = {24 00 65 00 6e 00 76 00 3a 00 5f 00 } //1 $env:_
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}
rule Trojan_Win32_ClickFix_DDM_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 [0-10] 3b 00 69 00 72 00 6d 00 20 00 2d 00 75 00 72 00 69 00 20 00 27 00 68 00 74 00 74 00 70 00 } //1
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_2 = {2d 00 46 00 6f 00 72 00 63 00 65 00 } //1 -Force
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
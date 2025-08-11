
rule Trojan_Win32_ClickFix_DEO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {5b 00 4e 00 65 00 74 00 2e 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 50 00 6f 00 69 00 6e 00 74 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5d 00 3a 00 3a 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 3d 00 } //10 [Net.ServicePointManager]::SecurityProtocol=
		$a_00_2 = {69 00 72 00 6d 00 20 00 24 00 } //10 irm $
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}
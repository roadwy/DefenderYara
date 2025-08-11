
rule Trojan_Win32_ClickFix_DFL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DFL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 00 57 00 2a 00 2a 00 33 00 32 00 63 00 3f 00 3f 00 6c 00 2e 00 65 00 2a 00 } //100 /W**32c??l.e*
		$a_00_1 = {57 00 2a 00 5c 00 2a 00 33 00 32 00 5c 00 63 00 3f 00 3f 00 6c 00 2e 00 65 00 2a 00 } //100 W*\*32\c??l.e*
		$a_00_2 = {2e 00 74 00 78 00 74 00 27 00 20 00 7c 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 .txt' | powershell
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*10) >=110
 
}
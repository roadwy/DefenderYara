
rule Trojan_Win32_ClickFix_GVG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GVG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffe9 03 ffffffe9 03 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {69 00 65 00 78 00 28 00 69 00 72 00 6d 00 28 00 24 00 } //500 iex(irm($
		$a_02_2 = {5b 00 73 00 74 00 72 00 69 00 6e 00 67 00 5d 00 24 00 [0-02] 2b 00 27 00 2e 00 27 00 2b 00 24 00 [0-02] 2b 00 27 00 2e 00 27 00 2b 00 24 00 [0-02] 2b 00 27 00 2e 00 27 00 2b 00 24 00 [0-02] 2b 00 24 00 [0-02] 3b 00 } //500
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*500+(#a_02_2  & 1)*500) >=1001
 
}

rule Trojan_Win32_ClickFix_DEC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffa0 00 ffffffa0 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_02_1 = {7b 00 26 00 20 00 28 00 64 00 69 00 72 00 20 00 [0-02] 5c 00 57 00 2a 00 [0-02] 5c 00 2a 00 33 00 32 00 [0-02] 5c 00 63 00 3f 00 3f 00 6c 00 2e 00 65 00 2a 00 29 00 } //50
		$a_00_2 = {7c 00 20 00 69 00 65 00 78 00 } //10 | iex
	condition:
		((#a_00_0  & 1)*100+(#a_02_1  & 1)*50+(#a_00_2  & 1)*10) >=160
 
}

rule Trojan_Win32_ClickFix_HA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 [0-02] 27 00 2c 00 27 00 27 00 29 00 } //10
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}

rule Trojan_Win32_DefenderControl_A{
	meta:
		description = "Trojan:Win32/DefenderControl.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 [0-20] 20 00 2f 00 53 00 59 00 53 00 20 00 } //1
		$a_02_1 = {64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 [0-20] 20 00 2f 00 54 00 49 00 20 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
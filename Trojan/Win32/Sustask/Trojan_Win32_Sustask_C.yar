
rule Trojan_Win32_Sustask_C{
	meta:
		description = "Trojan:Win32/Sustask.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 [0-f0] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-f0] 2f 00 74 00 72 00 [0-f0] 6d 00 6e 00 6f 00 6c 00 79 00 6b 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
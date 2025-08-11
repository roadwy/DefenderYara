
rule Trojan_Win32_SchExec_HI_MTB{
	meta:
		description = "Trojan:Win32/SchExec.HI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2e 00 61 00 75 00 33 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 [0-04] 20 00 2f 00 66 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
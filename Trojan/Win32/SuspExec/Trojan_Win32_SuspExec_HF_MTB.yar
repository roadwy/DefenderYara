
rule Trojan_Win32_SuspExec_HF_MTB{
	meta:
		description = "Trojan:Win32/SuspExec.HF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 [0-14] 5c 00 72 00 65 00 67 00 73 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 [0-06] 3a 00 5c 00 } //1
		$a_00_1 = {2e 00 64 00 6c 00 6c 00 } //-100 .dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*-100) >=1
 
}
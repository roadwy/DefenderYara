
rule Trojan_Win32_MpTamperSrvConn_A{
	meta:
		description = "Trojan:Win32/MpTamperSrvConn.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {72 00 6f 00 75 00 74 00 65 00 [0-30] 61 00 64 00 64 00 } //1
		$a_00_1 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //1 0.0.0.0
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
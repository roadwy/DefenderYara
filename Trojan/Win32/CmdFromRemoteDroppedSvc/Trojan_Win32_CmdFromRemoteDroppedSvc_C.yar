
rule Trojan_Win32_CmdFromRemoteDroppedSvc_C{
	meta:
		description = "Trojan:Win32/CmdFromRemoteDroppedSvc.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 [0-50] 70 00 75 00 73 00 68 00 64 00 20 00 5c 00 5c 00 } //1
		$a_02_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 [0-50] 70 00 75 00 73 00 68 00 64 00 20 00 5c 00 5c 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
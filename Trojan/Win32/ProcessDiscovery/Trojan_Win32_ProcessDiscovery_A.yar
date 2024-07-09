
rule Trojan_Win32_ProcessDiscovery_A{
	meta:
		description = "Trojan:Win32/ProcessDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {71 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 qprocess
		$a_02_1 = {71 00 75 00 65 00 72 00 79 00 [0-10] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
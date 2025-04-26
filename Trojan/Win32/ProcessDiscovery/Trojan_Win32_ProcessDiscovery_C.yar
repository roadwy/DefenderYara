
rule Trojan_Win32_ProcessDiscovery_C{
	meta:
		description = "Trojan:Win32/ProcessDiscovery.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 } //1 tasklist
		$a_00_1 = {2f 00 73 00 76 00 63 00 } //-1 /svc
		$a_00_2 = {2d 00 73 00 76 00 63 00 } //-1 -svc
		$a_00_3 = {64 00 65 00 76 00 65 00 6e 00 76 00 2e 00 65 00 78 00 65 00 } //-1 devenv.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*-1+(#a_00_2  & 1)*-1+(#a_00_3  & 1)*-1) >=1
 
}
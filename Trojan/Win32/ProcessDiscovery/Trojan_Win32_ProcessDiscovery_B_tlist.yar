
rule Trojan_Win32_ProcessDiscovery_B_tlist{
	meta:
		description = "Trojan:Win32/ProcessDiscovery.B!tlist,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 90 02 10 2f 00 73 00 76 00 63 00 90 00 } //1
		$a_00_1 = {49 00 50 00 20 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 53 00 6f 00 66 00 74 00 70 00 68 00 6f 00 6e 00 65 00 } //65526 IP Desktop Softphone
		$a_00_2 = {4d 00 79 00 4e 00 4f 00 45 00 50 00 68 00 6f 00 6e 00 65 00 49 00 50 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 65 00 78 00 65 00 } //65526 MyNOEPhoneIPDesktop.exe
		$a_00_3 = {4e 00 69 00 6e 00 74 00 65 00 6e 00 64 00 6f 00 2e 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 50 00 6f 00 72 00 74 00 61 00 6c 00 2e 00 65 00 78 00 65 00 } //65526 Nintendo.ProjectPortal.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*65526+(#a_00_2  & 1)*65526+(#a_00_3  & 1)*65526) >=1
 
}
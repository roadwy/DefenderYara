
rule Trojan_Win32_SystemDiscovery_B_sysinfo{
	meta:
		description = "Trojan:Win32/SystemDiscovery.B!sysinfo,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 79 00 73 00 74 00 65 00 6d 00 69 00 6e 00 66 00 6f 00 } //1 systeminfo
		$a_00_1 = {3e 00 20 00 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 5c 00 } //-10 > c:\programdata\microsoft\windows defender\support\
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*-10) >=1
 
}
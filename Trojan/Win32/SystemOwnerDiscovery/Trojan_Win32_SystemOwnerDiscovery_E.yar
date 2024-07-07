
rule Trojan_Win32_SystemOwnerDiscovery_E{
	meta:
		description = "Trojan:Win32/SystemOwnerDiscovery.E,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 6f 00 61 00 6d 00 69 00 } //10 whoami
		$a_00_1 = {5c 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 53 00 74 00 6f 00 72 00 65 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 } //-5 \VirtualStore\MACHINE\
		$a_00_2 = {5c 00 4f 00 66 00 66 00 69 00 63 00 65 00 5c 00 43 00 6c 00 69 00 63 00 6b 00 54 00 6f 00 52 00 75 00 6e 00 5c 00 } //-5 \Office\ClickToRun\
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*-5+(#a_00_2  & 1)*-5) >=10
 
}
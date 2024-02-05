
rule Trojan_Win32_QHosts_AL{
	meta:
		description = "Trojan:Win32/QHosts.AL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 6e 61 6d 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 20 73 65 72 76 69 63 65 } //01 00 
		$a_02_1 = {65 63 68 6f 20 90 10 03 00 2e 90 10 03 00 2e 90 10 03 00 2e 90 10 03 00 20 62 61 6e 63 6f 65 73 74 61 64 6f 2e 63 6c 20 3e 3e 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
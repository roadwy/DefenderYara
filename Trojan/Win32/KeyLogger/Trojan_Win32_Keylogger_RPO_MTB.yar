
rule Trojan_Win32_Keylogger_RPO_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 83 c1 01 89 4d fc 8b 55 f8 2b 55 f4 39 55 fc 73 1b 8b 4d f4 8b 7d 0c 8b 75 08 03 75 fc 33 c0 f3 a6 75 07 b8 01 00 00 00 eb 04 eb d1 } //01 00 
		$a_01_1 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_01_2 = {76 6d 77 61 72 65 } //00 00  vmware
	condition:
		any of ($a_*)
 
}
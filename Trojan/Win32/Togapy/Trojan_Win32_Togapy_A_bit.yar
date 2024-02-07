
rule Trojan_Win32_Togapy_A_bit{
	meta:
		description = "Trojan:Win32/Togapy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 44 6f 77 6e 46 69 6c 65 46 6c 6f 6f 64 } //01 00  WebDownFileFlood
		$a_00_1 = {8b 44 24 08 8a ca 03 c6 32 08 02 ca 46 3b 74 24 0c 88 08 } //01 00 
		$a_00_2 = {8a 4d 13 fe 4d ff 32 4d ff 88 4d 13 59 8a 4d 13 42 3b 55 0c 88 08 } //00 00 
	condition:
		any of ($a_*)
 
}
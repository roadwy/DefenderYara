
rule Trojan_Win32_Paramis_E{
	meta:
		description = "Trojan:Win32/Paramis.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 90 01 01 0f be 90 01 01 01 8b 4d 90 01 01 0f be 90 01 05 33 c2 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //01 00 
		$a_00_1 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
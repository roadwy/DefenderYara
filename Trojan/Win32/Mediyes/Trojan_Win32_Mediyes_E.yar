
rule Trojan_Win32_Mediyes_E{
	meta:
		description = "Trojan:Win32/Mediyes.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b c5 8a 54 38 ff 30 14 3b 83 c7 01 3b 7e 14 72 ca 83 7c 24 90 01 01 10 90 00 } //01 00 
		$a_01_1 = {53 00 36 00 17 00 1b 00 08 00 0d 00 22 00 3b 00 18 00 0f 00 07 00 17 00 00 00 } //01 00 
		$a_00_2 = {5c 00 5c 00 2e 00 5c 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 53 00 79 00 73 00 45 00 76 00 74 00 43 00 } //00 00 
	condition:
		any of ($a_*)
 
}
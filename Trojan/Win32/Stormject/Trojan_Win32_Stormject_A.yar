
rule Trojan_Win32_Stormject_A{
	meta:
		description = "Trojan:Win32/Stormject.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 6f 72 6d 20 64 64 6f 73 20 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 75 73 65 20 73 74 6f 72 6d 20 64 64 6f 73 } //01 00 
		$a_01_2 = {53 74 6f 72 6d 53 65 72 76 65 72 2e 64 6c 6c } //0a 00 
		$a_03_3 = {50 ff d3 ff d0 80 65 90 01 01 00 8b c8 c6 45 90 01 01 55 c6 45 90 01 01 70 c6 45 90 01 01 64 c6 45 90 01 01 61 c6 45 90 01 01 74 c6 45 90 01 01 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
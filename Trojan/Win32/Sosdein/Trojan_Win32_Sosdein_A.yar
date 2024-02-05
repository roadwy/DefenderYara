
rule Trojan_Win32_Sosdein_A{
	meta:
		description = "Trojan:Win32/Sosdein.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {74 1b 6a 02 68 90 01 01 fe ff ff 57 e8 90 01 03 00 83 c4 0c 85 c0 57 74 0a 90 00 } //01 00 
		$a_01_1 = {72 65 73 75 6c 74 3f 68 6c 3d 65 6e 26 6d 65 74 61 3d 25 73 } //01 00 
		$a_01_2 = {25 73 75 73 72 65 72 5f 5f 25 64 2e 69 6e 69 } //01 00 
		$a_01_3 = {25 64 7e 43 50 55 2f 25 75 7e 4d 48 7a } //00 00 
	condition:
		any of ($a_*)
 
}
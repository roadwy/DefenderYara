
rule Trojan_Win32_Alureon_FA{
	meta:
		description = "Trojan:Win32/Alureon.FA,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 26 } //01 00  &affid=%s&subid=%s&
		$a_01_1 = {5b 64 61 74 65 5f 62 65 67 69 6e 5d } //01 00  [date_begin]
		$a_01_2 = {4f 4b 5f 49 4e 53 54 41 4c 4c } //00 00  OK_INSTALL
	condition:
		any of ($a_*)
 
}

rule Backdoor_Win32_Pirpi_A{
	meta:
		description = "Backdoor:Win32/Pirpi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cb 7d 12 8a 5c 0c 90 01 01 32 da 80 c2 02 88 5c 0c 90 01 01 41 3b c8 7c ee 90 00 } //01 00 
		$a_01_1 = {75 60 8d 56 07 33 c9 8a 02 3c 30 7c 0f 3c 39 7f 0b } //00 00 
	condition:
		any of ($a_*)
 
}
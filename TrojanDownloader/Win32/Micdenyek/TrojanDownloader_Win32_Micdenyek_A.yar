
rule TrojanDownloader_Win32_Micdenyek_A{
	meta:
		description = "TrojanDownloader:Win32/Micdenyek.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {44 43 49 4d 5f 30 25 35 21 64 21 2e 6a 70 67 } //05 00 
		$a_03_1 = {25 31 21 73 21 5c 25 32 21 73 90 01 01 2e 64 6c 6c 90 00 } //05 00 
		$a_00_2 = {62 79 74 65 73 3d 25 31 21 64 21 } //00 00 
	condition:
		any of ($a_*)
 
}
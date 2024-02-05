
rule Worm_Win32_Vobfus_CL{
	meta:
		description = "Worm:Win32/Vobfus.CL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 2e 8d 95 90 01 05 ff 15 90 01 04 6a 63 ff 15 90 02 14 6a 6f ff 15 90 02 14 6a 6d 90 00 } //01 00 
		$a_03_1 = {6a 76 ff 15 90 02 14 6a 69 90 02 07 ff 15 90 01 04 6a 64 90 02 07 ff 15 90 01 04 6a 65 90 00 } //01 00 
		$a_03_2 = {6a 6c 8d 8d 90 01 05 ff 15 90 01 04 6a 2e 90 02 07 ff 15 90 01 04 6a 6f ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
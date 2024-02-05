
rule Worm_Win32_Vobfus_gen_I{
	meta:
		description = "Worm:Win32/Vobfus.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 05 00 00 00 c7 45 9c 01 00 00 00 c7 45 fc 06 00 00 00 8b 4d 08 8b 11 52 8b 4d 9c ff 15 90 01 04 50 6a ff 68 20 01 00 00 ff 15 90 00 } //01 00 
		$a_01_1 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 } //01 00 
		$a_01_2 = {5b 00 00 00 02 00 00 00 5d 00 00 00 } //01 00 
		$a_03_3 = {6a 00 6a 01 6a 01 6a 00 8d 90 09 17 00 c7 45 fc 90 01 01 00 00 00 66 c7 05 90 01 04 ff ff c7 45 fc 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_4 = {56 42 2e 46 72 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}
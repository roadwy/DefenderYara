
rule Ransom_Win32_GandCrab_MTD_bit{
	meta:
		description = "Ransom:Win32/GandCrab.MTD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 6a 64 6a 00 ff 15 90 01 04 8b f0 68 90 01 04 56 ff 15 90 01 04 c6 46 90 01 02 8b c6 5e c3 90 00 } //01 00 
		$a_03_1 = {55 8b ec 8b c1 c1 e0 04 03 c2 8b d1 03 4d 90 01 01 c1 ea 05 03 55 90 01 01 33 c2 33 c1 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
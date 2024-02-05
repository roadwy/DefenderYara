
rule Worm_Win32_Vobfus_BI{
	meta:
		description = "Worm:Win32/Vobfus.BI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 02 00 00 00 6a ff e8 90 01 04 c7 45 fc 03 00 00 00 ff 75 b8 e8 90 01 04 50 e8 90 01 04 89 45 d8 90 00 } //01 00 
		$a_03_1 = {ff 75 b4 8d 45 ac 50 e8 90 01 04 50 ff 75 d8 e8 90 01 04 89 45 88 ff 75 ac 8d 45 b4 50 e8 90 01 04 8b 45 88 89 45 d4 8d 4d ac e8 90 01 04 c7 45 fc 90 01 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
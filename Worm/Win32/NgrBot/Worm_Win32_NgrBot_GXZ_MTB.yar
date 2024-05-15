
rule Worm_Win32_NgrBot_GXZ_MTB{
	meta:
		description = "Worm:Win32/NgrBot.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {23 d8 88 9d 90 01 04 0f b6 85 90 01 04 0f b6 8d 90 01 04 8d 54 08 90 01 01 88 55 90 01 01 0f b6 45 90 01 01 83 c0 46 0f b7 4d 90 01 01 33 c8 66 89 4d 90 01 01 0f b7 55 90 01 01 0f b6 85 90 01 04 2b d0 0f b6 8d 90 01 04 8d 54 0a 90 01 01 0f b6 85 90 01 04 2b d0 88 95 90 01 04 0f b6 8d 90 01 04 0f b6 55 90 01 01 3b ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
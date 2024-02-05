
rule Worm_Win32_Pizbot{
	meta:
		description = "Worm:Win32/Pizbot,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {66 33 45 d0 0f bf d0 52 ff 15 90 01 04 8b d0 8d 4d c8 ff 15 90 01 04 50 ff 15 90 01 04 8b d0 8d 4d d4 ff 15 90 00 } //0a 00 
		$a_03_1 = {66 33 45 d0 0f bf c0 50 e8 90 01 04 8b d0 8d 4d c8 e8 90 01 04 50 e8 90 01 04 8b d0 8d 4d d4 e8 90 00 } //05 00 
		$a_03_2 = {c7 45 fc 04 00 00 00 6a 00 6a 00 6a 10 8b 45 dc 50 e8 90 01 02 ff ff ff 15 90 01 04 c7 45 f0 00 00 00 00 68 90 01 04 eb 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
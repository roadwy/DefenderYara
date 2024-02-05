
rule Worm_Win32_Gamarue_AA{
	meta:
		description = "Worm:Win32/Gamarue.AA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 1f 8b 15 90 01 04 03 55 90 01 01 0f b6 02 33 45 90 01 01 03 45 fc 8b 0d 90 01 04 03 4d 90 01 01 88 01 eb cd ff 15 90 01 04 81 7d 14 ff ff ff 07 75 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
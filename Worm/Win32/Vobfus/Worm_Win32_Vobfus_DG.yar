
rule Worm_Win32_Vobfus_DG{
	meta:
		description = "Worm:Win32/Vobfus.DG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 6a 8b 55 f4 52 e8 90 01 04 83 c4 08 8b 4d 08 03 4d f8 88 01 83 7d f8 40 7d 0b 90 00 } //01 00 
		$a_01_1 = {52 6a 00 6a 00 68 d0 2e 40 00 6a 00 6a 00 ff 55 f4 89 45 f8 e9 c2 fe ff ff } //01 00 
		$a_01_2 = {6a 04 6a 0d 8b 45 fc 50 68 34 02 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
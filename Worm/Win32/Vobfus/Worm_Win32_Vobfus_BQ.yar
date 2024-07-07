
rule Worm_Win32_Vobfus_BQ{
	meta:
		description = "Worm:Win32/Vobfus.BQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 55 84 8b 85 2c ff ff ff c1 e0 04 8b 0d 90 01 04 03 c8 ff 15 90 01 02 40 00 c7 45 fc 1a 00 00 00 e8 90 01 02 03 00 c7 45 fc 1b 00 00 00 e8 90 01 02 02 00 c7 45 fc 1c 00 00 00 c7 45 8c 24 51 40 00 c7 45 84 08 00 00 00 c7 85 2c ff ff ff 6f 44 00 00 81 bd 2c ff ff ff 61 ea 00 00 73 0c c7 85 94 fe ff ff 00 00 00 00 eb 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
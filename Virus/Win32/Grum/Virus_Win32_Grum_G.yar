
rule Virus_Win32_Grum_G{
	meta:
		description = "Virus:Win32/Grum.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 40 00 00 6a 00 ff 73 90 01 01 6a ff ff 93 90 01 02 00 00 8b 73 90 01 01 0b f6 74 56 03 73 90 01 01 8b 7e 10 03 7b 90 01 01 8b 4e 0c 0b c9 74 46 03 4b 90 01 01 6a 00 6a 00 51 ff 93 90 01 02 00 00 8b c8 56 8b 06 0b c0 75 03 8b 46 10 8b f0 03 73 90 01 01 ad 0b c0 74 1c 79 07 25 ff ff ff 7f eb 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
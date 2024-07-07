
rule Virus_Win32_Autorun_OE{
	meta:
		description = "Virus:Win32/Autorun.OE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 85 f4 fe ff ff 68 38 16 40 00 50 ff d6 59 c7 45 fc 01 00 00 00 85 c0 59 74 03 89 5d fc 8d 85 d0 fe ff ff 50 57 e8 49 12 00 00 85 c0 75 bd 39 5d fc 75 44 53 be 18 16 40 00 53 56 68 f0 15 40 00 53 e8 57 12 00 00 53 53 53 56 8b 35 80 13 40 00 68 e8 15 40 00 53 ff d6 53 bf c8 15 40 00 53 57 68 a0 15 40 00 53 e8 32 12 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
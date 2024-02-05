
rule Virus_Win32_Virut{
	meta:
		description = "Virus:Win32/Virut,SIGNATURE_TYPE_PEHSTR,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 dc 2d 00 01 89 85 e4 fd ff ff e9 f8 2e 01 00 01 8b 4d fc 33 cd e8 c0 fc ff ff } //01 00 
		$a_01_1 = {85 c0 f7 d2 90 0f 84 7e 44 00 00 ba d1 8e a8 3f } //00 00 
	condition:
		any of ($a_*)
 
}
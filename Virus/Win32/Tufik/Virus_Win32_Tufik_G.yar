
rule Virus_Win32_Tufik_G{
	meta:
		description = "Virus:Win32/Tufik.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 fc 60 c7 45 fc 00 00 00 00 e8 00 00 00 00 5b 81 eb 90 01 01 16 40 00 55 8d 83 90 01 01 17 40 00 50 8d 83 90 01 01 16 40 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 8b 7d 08 81 e7 00 00 ff ff 66 81 3f 4d 5a 75 11 8b f7 03 76 3c 66 81 3e 50 45 75 05 89 7d fc eb 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
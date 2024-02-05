
rule Virus_Win32_Sality_AU{
	meta:
		description = "Virus:Win32/Sality.AU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_07_0 = {81 ed 05 10 40 00 8a 9d 73 27 40 00 84 db 74 13 81 c4 90 01 04 2d 90 01 04 89 85 90 01 01 12 40 00 eb 19 c7 85 90 01 01 14 40 00 22 22 22 22 c7 85 90 01 01 14 40 00 33 33 33 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
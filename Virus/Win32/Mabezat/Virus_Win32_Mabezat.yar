
rule Virus_Win32_Mabezat{
	meta:
		description = "Virus:Win32/Mabezat,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec d8 06 00 00 53 56 57 90 03 09 09 b8 90 01 04 b9 00 00 00 00 b9 00 00 00 00 b8 90 01 04 8a 90 01 01 80 90 01 02 88 90 01 01 83 90 01 01 01 83 90 01 01 01 81 f9 90 90 05 00 00 75 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
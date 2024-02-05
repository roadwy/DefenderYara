
rule Virus_Win32_Hematite_gen_A{
	meta:
		description = "Virus:Win32/Hematite.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 ef ff 75 10 ff 95 90 01 02 00 00 ff 75 90 01 01 ff 95 90 01 02 00 00 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 81 c1 90 01 02 00 00 e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
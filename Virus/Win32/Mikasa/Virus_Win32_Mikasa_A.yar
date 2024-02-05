
rule Virus_Win32_Mikasa_A{
	meta:
		description = "Virus:Win32/Mikasa.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 51 52 51 54 53 50 51 51 6a 02 51 51 6a 03 52 ff 55 30 50 96 ff 55 00 56 ff 55 34 ff 55 04 ff 55 18 cc 4d 00 5a 01 50 } //00 00 
	condition:
		any of ($a_*)
 
}
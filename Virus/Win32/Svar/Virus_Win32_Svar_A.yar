
rule Virus_Win32_Svar_A{
	meta:
		description = "Virus:Win32/Svar.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c8 90 02 00 8b fc 54 50 ff 56 0c 95 33 db 60 53 53 6a 03 53 53 6a 03 8d 57 2c 52 ff 56 14 50 50 53 53 8b 6f 20 55 50 53 81 c5 00 20 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
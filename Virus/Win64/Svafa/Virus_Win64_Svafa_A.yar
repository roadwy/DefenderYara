
rule Virus_Win64_Svafa_A{
	meta:
		description = "Virus:Win64/Svafa.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c8 40 01 00 55 54 5e 56 5a 48 83 ec 28 ff 57 18 48 95 48 33 db 55 53 53 6a 03 48 83 ec 20 4d 33 c9 4d 33 c0 6a 03 5a 48 8d 4e 2c ff 57 30 48 83 c4 38 } //00 00 
	condition:
		any of ($a_*)
 
}
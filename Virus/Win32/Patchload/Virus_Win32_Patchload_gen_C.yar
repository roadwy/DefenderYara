
rule Virus_Win32_Patchload_gen_C{
	meta:
		description = "Virus:Win32/Patchload.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_02_0 = {68 78 65 63 00 68 57 69 6e 45 90 0a 35 00 47 65 74 50 90 02 10 72 6f 63 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
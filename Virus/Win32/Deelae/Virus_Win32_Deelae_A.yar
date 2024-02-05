
rule Virus_Win32_Deelae_A{
	meta:
		description = "Virus:Win32/Deelae.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 ff 32 64 89 22 e8 00 00 00 00 f9 19 34 24 64 ad 8b 40 0c 8b 70 1c ad 8b 68 08 e8 20 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
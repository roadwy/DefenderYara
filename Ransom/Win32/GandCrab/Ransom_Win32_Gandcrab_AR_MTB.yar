
rule Ransom_Win32_Gandcrab_AR_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 6b 00 00 00 90 02 02 89 90 01 05 a3 90 01 04 bb 72 00 00 00 b8 65 00 00 00 8b cb 90 02 02 89 90 01 05 ba 6e 00 00 00 90 02 02 89 90 02 1f b9 6c 00 00 00 ba 33 00 00 00 90 02 02 89 90 02 07 89 90 02 05 b8 32 00 00 00 90 02 07 b9 2e 00 00 00 ba 64 00 00 00 b8 6c 00 00 00 66 89 0d 90 01 04 66 89 15 90 01 04 8b c8 33 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
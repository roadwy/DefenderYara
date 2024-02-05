
rule Ransom_Win32_GandCrab_AF_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e3 1d 81 90 01 02 94 4a c6 41 81 90 01 02 94 4a c6 41 83 90 01 02 40 8b 55 90 01 01 a1 90 01 04 8d 4d 90 01 01 51 8b 0d 90 01 04 52 50 51 ff 15 90 01 04 e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
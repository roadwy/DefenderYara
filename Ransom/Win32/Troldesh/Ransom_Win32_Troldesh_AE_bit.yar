
rule Ransom_Win32_Troldesh_AE_bit{
	meta:
		description = "Ransom:Win32/Troldesh.AE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 08 8b 02 8b 4d fc 8d 94 01 90 01 04 8b 45 08 89 10 8b 4d 08 8b 11 81 ea 90 01 04 8b 45 08 89 10 90 00 } //01 00 
		$a_03_1 = {8b 11 89 15 90 01 04 a1 90 01 04 83 e8 01 a3 90 01 04 8b 15 90 01 04 83 c2 01 a1 90 01 04 8b ff 8b ca a3 90 01 04 31 0d 90 01 04 a1 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 8b ff 01 05 90 01 04 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
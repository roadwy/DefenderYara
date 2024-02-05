
rule Ransom_Win32_CubaPacker_SA_MTB{
	meta:
		description = "Ransom:Win32/CubaPacker.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 b4 33 85 90 01 04 c1 c0 90 01 01 03 f0 89 5d 90 01 01 89 75 90 01 01 89 75 90 01 01 33 f1 8b 4d 90 01 01 c1 c6 90 01 01 89 75 90 01 01 03 ce 89 75 90 01 01 8b 75 90 01 01 89 4d 90 01 01 89 4d 90 01 01 33 c8 c1 c1 90 01 01 83 6d 90 01 02 89 4d 90 01 01 89 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
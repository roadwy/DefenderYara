
rule Ransom_Win32_StopCrypt_PBI_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c3 81 00 e1 34 ef c6 c3 55 8b ec } //01 00 
		$a_03_1 = {b8 fe 93 8d 6a 33 ca 31 4d 90 01 01 81 3d 90 01 04 a3 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
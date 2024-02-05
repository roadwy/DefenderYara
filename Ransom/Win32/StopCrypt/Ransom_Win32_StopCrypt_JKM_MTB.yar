
rule Ransom_Win32_StopCrypt_JKM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.JKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 44 24 28 c7 05 90 01 08 33 c6 33 c1 2b d8 89 44 24 90 01 01 8b c3 c1 e0 90 01 01 81 3d 90 01 08 89 44 24 10 75 90 00 } //01 00 
		$a_03_1 = {ff 15 50 10 40 00 31 74 24 10 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 3d 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Ransom_Win32_StopCrypt_SLU_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ca 8b c2 c1 e8 90 01 01 c1 e1 90 01 01 03 4d 90 01 01 03 c3 33 c1 33 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 05 90 01 04 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 c7 89 45 90 01 01 8b 45 90 01 01 03 45 90 00 } //01 00 
		$a_03_1 = {8b 45 0c 01 45 90 01 01 83 6d fc 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
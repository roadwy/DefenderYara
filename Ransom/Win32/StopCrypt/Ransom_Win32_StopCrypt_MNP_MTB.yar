
rule Ransom_Win32_StopCrypt_MNP_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 f8 8d 45 f8 e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {8b c2 d3 e8 89 35 90 01 04 03 45 90 01 01 89 45 f8 33 c7 31 45 fc 8b 45 90 01 01 89 45 90 01 01 8b 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
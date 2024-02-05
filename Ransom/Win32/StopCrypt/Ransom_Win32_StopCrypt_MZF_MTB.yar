
rule Ransom_Win32_StopCrypt_MZF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8d 0c 03 8b 45 90 02 01 c1 e8 90 02 01 89 45 90 02 01 8b 45 90 02 01 33 f1 8b 4d 90 02 01 03 c1 33 c6 83 3d 90 02 04 27 c7 05 90 02 08 89 45 fc 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Ransom_Win32_StopCrypt_COF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.COF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 f8 8b 4d fc 33 4d f0 8b 45 f8 03 45 dc 33 c1 89 4d fc 8b 0d 90 01 04 c7 05 90 01 04 ee 3d ea f4 89 45 f8 81 f9 13 02 00 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
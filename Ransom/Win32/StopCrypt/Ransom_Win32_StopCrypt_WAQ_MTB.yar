
rule Ransom_Win32_StopCrypt_WAQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.WAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f7 d3 ee 8d 04 3b 89 45 e0 c7 05 90 01 04 ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 33 75 fc 81 3d 90 01 04 13 02 00 00 75 90 00 } //01 00 
		$a_03_1 = {8b c6 8d 4d fc e8 90 01 04 8b 45 dc 01 45 fc 8b 4d f8 8d 04 33 31 45 fc d3 ee 03 75 d8 81 3d 90 01 04 21 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Ransom_Win32_StopCrypt_SHZ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f3 d3 ee 03 c3 89 45 e4 03 75 dc 8b 45 e4 31 45 fc 81 3d 90 01 04 03 0b 00 00 75 90 00 } //01 00 
		$a_03_1 = {31 75 fc 8b 45 fc 29 45 ec 8b 45 d4 29 45 90 01 01 ff 4d e0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
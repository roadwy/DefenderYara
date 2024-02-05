
rule Ransom_Win32_StopCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 90 01 08 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 00 } //01 00 
		$a_03_1 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 81 45 90 01 05 31 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_SN_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 d2 85 ff 7e 90 01 01 eb 90 01 01 8d 49 00 e8 90 01 02 ff ff 30 04 16 42 3b d7 7c 90 00 } //02 00 
		$a_03_1 = {50 6a 00 ff 15 90 01 04 a3 90 01 04 81 3d 90 01 08 75 90 01 01 c7 05 90 01 08 eb 90 01 01 c7 85 90 01 04 00 00 00 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
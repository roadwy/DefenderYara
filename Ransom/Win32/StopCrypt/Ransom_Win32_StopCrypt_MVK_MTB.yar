
rule Ransom_Win32_StopCrypt_MVK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e9 05 89 4d ec 8b 55 ec 03 55 d4 89 55 ec 8b 45 e4 33 45 f0 89 45 e4 8b 4d e4 33 4d ec 89 4d e4 8b 45 e4 29 45 d0 8b 55 d8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_MVK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 33 44 24 90 02 01 c2 90 02 02 81 00 90 02 04 c3 90 00 } //01 00 
		$a_03_1 = {c1 e0 04 89 01 c3 81 00 90 02 04 c3 29 08 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
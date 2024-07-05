
rule Ransom_Win32_TeslaCrypt_NM_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {38 ea 89 44 24 90 01 01 88 4c 24 2f 0f 87 90 01 04 e9 a6 00 00 00 8b 44 24 90 00 } //03 00 
		$a_03_1 = {58 89 44 24 90 01 01 e9 f6 00 00 00 8a 84 24 90 01 04 34 b6 8b 4c 24 4c 8a 54 24 90 01 01 83 c1 01 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
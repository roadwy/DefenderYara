
rule Ransom_Win32_StopCrypt_PBX_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b cb c1 e1 04 03 4c 24 90 01 01 89 15 90 01 04 33 4c 24 90 01 01 33 4c 24 90 01 01 2b f9 89 7c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
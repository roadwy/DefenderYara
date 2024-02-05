
rule Ransom_Win32_StopCrypt_SLT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f7 d3 e6 89 5c 24 90 01 01 03 74 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 8b d7 d3 ea 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 00 } //01 00 
		$a_03_1 = {33 44 24 10 89 1d 90 01 04 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 81 44 24 28 90 01 04 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
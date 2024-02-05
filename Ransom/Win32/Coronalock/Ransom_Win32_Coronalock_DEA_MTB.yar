
rule Ransom_Win32_Coronalock_DEA_MTB{
	meta:
		description = "Ransom:Win32/Coronalock.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c3 81 3d 90 01 04 72 05 00 00 90 13 31 44 24 10 8b d3 c1 ea 05 03 54 24 2c 89 54 24 24 8b 44 24 24 31 44 24 10 2b 74 24 10 8b 44 24 30 d1 6c 24 18 29 44 24 14 ff 4c 24 1c 0f 85 90 01 04 8b 44 24 34 5f 89 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
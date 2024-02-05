
rule Ransom_Win32_StopCrypt_SAA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 03 c6 89 45 90 01 01 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 31 55 90 01 01 89 3d 90 01 04 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
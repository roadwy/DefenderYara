
rule Ransom_Win32_StopCrypt_SAE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 33 45 90 01 01 83 25 90 01 05 2b d8 89 45 90 01 01 8b c3 c1 e0 90 01 01 89 5d 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
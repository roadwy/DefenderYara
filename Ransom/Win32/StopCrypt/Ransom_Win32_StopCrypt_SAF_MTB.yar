
rule Ransom_Win32_StopCrypt_SAF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 c5 89 44 24 90 01 01 33 44 24 90 01 01 31 44 24 90 01 01 8b 44 90 01 01 18 89 44 90 01 01 2c 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8d 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
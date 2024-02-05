
rule Ransom_Win32_StopCrypt_QWE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.QWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 54 24 90 01 01 8b 44 24 34 01 44 24 90 01 01 8b 44 24 24 31 44 90 01 01 10 8b 44 24 90 01 01 8b 4c 24 14 50 51 8d 54 24 90 01 01 52 e8 90 01 04 8b 4c 24 10 8d 44 24 2c e8 90 01 04 8d 44 24 28 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
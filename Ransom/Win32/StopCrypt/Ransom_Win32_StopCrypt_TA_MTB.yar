
rule Ransom_Win32_StopCrypt_TA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 33 c7 31 45 90 01 01 89 35 90 01 04 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
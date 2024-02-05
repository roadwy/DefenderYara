
rule Ransom_Win32_StopCrypt_SW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 45 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 29 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
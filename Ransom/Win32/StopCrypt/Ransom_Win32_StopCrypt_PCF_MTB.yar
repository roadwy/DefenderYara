
rule Ransom_Win32_StopCrypt_PCF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 55 90 01 01 c1 e0 04 03 45 90 01 01 89 4d 90 01 01 33 d0 33 d1 89 55 90 01 01 8b 45 90 02 10 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 c1 e0 04 03 45 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
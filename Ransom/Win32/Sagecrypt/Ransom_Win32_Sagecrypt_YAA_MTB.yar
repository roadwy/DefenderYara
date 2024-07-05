
rule Ransom_Win32_Sagecrypt_YAA_MTB{
	meta:
		description = "Ransom:Win32/Sagecrypt.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 34 03 c1 8a 0c 13 8b 54 24 2c 32 c8 85 d2 74 0d 8b 54 24 90 01 01 88 0c 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
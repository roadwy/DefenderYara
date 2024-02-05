
rule Ransom_Win32_StopCrypt_SO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 0c 07 33 4d 90 01 01 89 35 90 01 04 33 4d 90 01 01 89 4d 90 01 01 8b 45 90 01 01 01 05 90 00 } //01 00 
		$a_03_1 = {c1 e8 05 03 45 90 01 01 68 90 01 04 33 45 90 01 01 c7 05 90 01 08 33 c7 2b d8 8d 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
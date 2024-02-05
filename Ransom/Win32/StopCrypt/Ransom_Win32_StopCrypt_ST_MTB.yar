
rule Ransom_Win32_StopCrypt_ST_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 45 0c 33 f8 89 7d 90 01 01 8b 45 90 01 01 29 45 90 01 01 89 75 90 01 01 8b 45 90 01 01 01 45 90 01 01 2b 5d 90 01 01 ff 4d 90 01 01 89 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
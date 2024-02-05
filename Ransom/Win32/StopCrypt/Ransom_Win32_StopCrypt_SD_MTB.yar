
rule Ransom_Win32_StopCrypt_SD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 8d 14 06 c1 e1 90 01 01 03 4d 90 01 01 c1 e8 90 01 01 03 45 90 01 01 33 ca 33 c1 89 4d 90 01 01 89 45 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
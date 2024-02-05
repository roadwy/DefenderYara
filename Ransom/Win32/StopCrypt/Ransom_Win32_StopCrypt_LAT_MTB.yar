
rule Ransom_Win32_StopCrypt_LAT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.LAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 14 30 8b c6 8b 75 d4 d3 e8 8b 4d fc 03 ce 03 45 90 01 01 33 c1 33 c2 29 45 f0 89 45 fc 8b 45 dc 29 45 f8 ff 4d e4 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
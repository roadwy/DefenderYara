
rule Ransom_Win32_StopCrypt_PBT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c8 31 4d 90 01 01 c7 05 90 02 0a 8b 45 90 01 01 01 05 90 01 04 2b 75 90 01 01 c7 05 90 02 0a 8b ce c1 e1 04 03 4d 90 01 01 8b c6 c1 e8 05 03 45 90 01 01 8d 14 33 33 ca 33 c8 2b f9 81 3d 90 02 0a c7 05 90 02 0a 89 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
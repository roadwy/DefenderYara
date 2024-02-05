
rule Ransom_Win32_StopCrypt_PBS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 7d 90 01 01 c1 e7 04 03 7d 90 01 01 33 7d 90 01 01 81 3d 90 01 04 21 01 00 00 75 90 02 20 33 7d 90 01 01 89 35 90 01 04 89 7d 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
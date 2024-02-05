
rule Ransom_Win32_StopCrypt_SZ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 33 5d 90 01 01 31 5d 90 01 01 83 3d 90 01 05 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
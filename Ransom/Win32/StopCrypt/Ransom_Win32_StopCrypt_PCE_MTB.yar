
rule Ransom_Win32_StopCrypt_PCE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 90 01 01 8b 4c 24 90 01 01 33 74 24 90 01 01 03 4c 24 90 01 01 c7 05 90 02 0a 33 ce 83 3d 90 02 08 89 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
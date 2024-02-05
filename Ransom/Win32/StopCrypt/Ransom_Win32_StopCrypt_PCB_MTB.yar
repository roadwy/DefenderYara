
rule Ransom_Win32_StopCrypt_PCB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 8b 44 24 90 01 01 03 c5 33 c1 83 3d 90 02 08 c7 05 90 02 0a 89 4c 24 90 01 01 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
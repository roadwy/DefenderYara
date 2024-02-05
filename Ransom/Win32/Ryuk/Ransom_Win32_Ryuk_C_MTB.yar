
rule Ransom_Win32_Ryuk_C_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0b 0b 00 00 75 90 09 33 00 8b 4d 90 01 01 2b 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 c1 e2 04 89 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 c1 ea 05 89 55 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
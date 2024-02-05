
rule Ransom_Win32_StopCrypt_SLB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 f8 89 45 90 01 01 8b 55 90 01 01 8b 4d 90 01 01 d3 e2 8b 45 90 01 01 33 c2 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 8b 55 90 01 01 0b d1 89 55 90 01 01 83 7d 90 00 } //01 00 
		$a_03_1 = {2b c8 89 4d 90 01 01 8b 55 90 01 01 6b d2 90 01 01 8b 45 90 01 01 0b c2 89 45 90 01 01 8b 4d 90 01 01 83 f1 90 01 01 8b 55 90 01 01 33 d1 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
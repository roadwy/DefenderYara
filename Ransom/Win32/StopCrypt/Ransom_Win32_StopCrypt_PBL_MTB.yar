
rule Ransom_Win32_StopCrypt_PBL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c3 33 f0 33 75 90 01 01 89 75 90 01 01 8b 45 90 01 01 01 05 90 01 04 83 0d 90 02 06 2b fe 8b c7 c1 e0 04 03 45 90 01 01 8b d7 89 45 90 01 01 8b 45 90 01 01 03 c7 50 8d 45 90 01 01 c1 ea 05 03 55 90 01 01 50 c7 05 90 01 04 b4 21 e1 c5 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
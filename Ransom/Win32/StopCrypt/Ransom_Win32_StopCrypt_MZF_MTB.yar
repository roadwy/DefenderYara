
rule Ransom_Win32_StopCrypt_MZF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8d 0c 03 8b 45 [0-01] c1 e8 [0-01] 89 45 [0-01] 8b 45 [0-01] 33 f1 8b 4d [0-01] 03 c1 33 c6 83 3d [0-04] 27 c7 05 [0-08] 89 45 fc 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
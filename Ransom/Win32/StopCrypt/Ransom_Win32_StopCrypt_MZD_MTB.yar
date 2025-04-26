
rule Ransom_Win32_StopCrypt_MZD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 [0-01] 03 45 d4 89 45 f8 8d 04 0b 89 45 d8 8b 45 d8 31 45 f8 c1 e9 [0-01] 03 4d e0 89 3d [0-04] 31 4d f8 8b 45 f8 29 45 f0 81 c3 [0-04] ff 4d e8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
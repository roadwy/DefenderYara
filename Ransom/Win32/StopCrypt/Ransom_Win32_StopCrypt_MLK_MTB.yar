
rule Ransom_Win32_StopCrypt_MLK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 d0 2b 45 e4 89 45 d0 81 3d [0-06] 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
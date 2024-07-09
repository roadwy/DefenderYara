
rule Ransom_Win32_StopCrypt_BHG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.BHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 01 45 f8 8b 4d f0 8b 45 f4 8b d7 d3 ea 03 c7 03 55 ?? 33 d0 31 55 f8 8b 45 f8 29 45 ec 8b 45 e0 29 45 f4 ff 4d e4 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
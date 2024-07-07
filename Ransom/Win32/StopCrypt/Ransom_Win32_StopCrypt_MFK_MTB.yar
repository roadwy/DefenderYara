
rule Ransom_Win32_StopCrypt_MFK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 4d e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 90 02 08 c7 05 90 02 08 8b 55 f4 8b 8d 90 02 04 d3 ea 89 55 ec 8b 45 ec 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
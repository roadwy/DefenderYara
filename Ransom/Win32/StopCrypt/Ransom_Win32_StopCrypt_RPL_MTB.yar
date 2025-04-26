
rule Ransom_Win32_StopCrypt_RPL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e0 89 45 e4 8b 4d e4 03 4d f8 89 4d e4 8b 55 f4 03 55 e8 89 55 f0 c7 85 3c ff ff ff 00 00 00 00 8b 45 f4 c1 e8 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
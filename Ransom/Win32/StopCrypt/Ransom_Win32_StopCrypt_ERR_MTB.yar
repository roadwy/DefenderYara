
rule Ransom_Win32_StopCrypt_ERR_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.ERR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 45 f4 8b 45 d4 01 45 f4 8b 45 fc 33 45 e4 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45 fc 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
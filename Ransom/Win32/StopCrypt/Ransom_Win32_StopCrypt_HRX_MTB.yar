
rule Ransom_Win32_StopCrypt_HRX_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.HRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 18 8b c3 d3 e8 8b 4d fc 03 cf 03 45 dc 33 c1 33 c2 29 45 f0 89 45 fc 8d 45 f4 e8 ?? ?? ?? ?? ff 4d e8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
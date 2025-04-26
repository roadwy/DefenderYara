
rule Ransom_Win32_StopCrypt_JAB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.JAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 8d 4d fc e8 ?? ?? ?? ?? 8b 4d f8 8b 45 f0 8b 7d e0 d3 e8 8b 4d fc 03 cf 03 d3 03 45 dc 81 c3 47 86 c8 61 33 c1 33 c2 29 45 f4 ff 4d e8 89 45 fc 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
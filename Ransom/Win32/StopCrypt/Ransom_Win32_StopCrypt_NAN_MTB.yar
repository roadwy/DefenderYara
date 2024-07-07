
rule Ransom_Win32_StopCrypt_NAN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.NAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 45 f8 8d 0c 03 89 4d f0 8b 4d f4 d3 e8 03 45 d4 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 7d fc 81 c3 47 86 c8 61 ff 4d e4 89 7d ec 0f 85 c1 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
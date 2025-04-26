
rule Ransom_Win32_PlayCrypt_MKU_MTB{
	meta:
		description = "Ransom:Win32/PlayCrypt.MKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b d1 07 0f b6 44 15 e0 03 85 e0 fe ff ff 2b 85 e8 fe ff ff b9 02 00 00 00 6b d1 03 66 89 84 15 ?? ?? ff ff b8 01 00 00 00 d1 e0 0f b6 4c 05 e0 ba 01 00 00 00 6b c2 00 88 4c 05 e0 8b 8d 98 fe ff ff 3b 8d 9c fe ff ff 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
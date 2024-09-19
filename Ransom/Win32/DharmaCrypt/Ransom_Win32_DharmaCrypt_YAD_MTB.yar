
rule Ransom_Win32_DharmaCrypt_YAD_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 8d 57 b6 ff ff 8b 95 7c b6 ff ff 32 ca 8b bd 94 b6 ff ff 03 95 64 b6 ff ff 89 95 7c b6 ff ff 88 0c 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
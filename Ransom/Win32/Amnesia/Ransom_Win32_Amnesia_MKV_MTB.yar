
rule Ransom_Win32_Amnesia_MKV_MTB{
	meta:
		description = "Ransom:Win32/Amnesia.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 89 45 e8 0f b6 84 9d e4 fb ff ff 8b 55 e8 8b 94 95 e4 fb ff ff 89 94 9d e4 fb ff ff 0f b6 c0 8b 55 e8 89 84 95 e4 fb ff ff 8b 84 9d e4 fb ff ff 8b 55 e8 03 84 95 e4 fb ff ff 25 ?? ?? ?? ?? 79 ?? 48 0d 00 ff ff ff 40 0f b6 84 85 e4 fb ff ff 8b 55 f0 30 04 32 46 ff 4d e4 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
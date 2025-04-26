
rule Trojan_Win32_Pikabot_FN_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 d2 8a 84 15 e8 fb ff ff 01 c1 88 85 d4 fa ff ff 0f b6 c9 8a 84 0d e8 fb ff ff 88 84 15 e8 fb ff ff 8a 85 d4 fa ff ff 88 84 0d e8 fb ff ff 02 84 15 e8 fb ff ff 0f b6 c0 8a 84 05 e8 fb ff ff 32 84 2b 76 fb ff ff 0f b6 c0 66 89 84 5d 9c fb ff ff 43 83 fb 26 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win32_ParallaxRat_APA_MTB{
	meta:
		description = "Trojan:Win32/ParallaxRat.APA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 13 02 00 00 6a 00 6a 00 6a 00 6a 00 8b 45 ec 50 8b 55 f4 8b 45 fc 8b 80 90 00 00 00 e8 76 34 fb ff 50 e8 98 4d fa ff ff 4d f4 83 7d f4 ff } //2
		$a_01_1 = {8b ec 83 c4 f0 89 4d f4 89 55 f8 89 45 fc 68 fc 69 40 00 68 10 6a 40 00 e8 02 fa ff ff 89 45 f0 68 18 6a 40 00 e8 65 fc ff ff 8b 55 fc 89 02 68 28 6a 40 00 e8 56 fc ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}

rule Ransom_Win32_GrandCrab_CR_MTB{
	meta:
		description = "Ransom:Win32/GrandCrab.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 ff d3 8d 45 90 01 01 50 ff 15 90 01 03 00 8d 4d 90 01 01 51 6a 00 6a 00 ff 15 90 01 03 00 e8 90 01 04 30 04 3e 46 3b 75 90 00 } //1
		$a_00_1 = {c6 85 27 fb ff ff 50 88 85 2d fb ff ff 88 85 23 fb ff ff 88 85 2a fb ff ff c6 85 2c fb ff ff 63 88 8d 22 fb ff ff c6 85 2e fb ff ff 00 33 f6 8d 9b 00 00 00 00 81 fe } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
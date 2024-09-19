
rule Trojan_Win32_Neoreblamy_RU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 89 45 d8 8b 45 d8 89 45 e4 33 c9 8b 45 e0 ba 04 00 00 00 f7 e2 0f 90 c1 f7 d9 0b c8 51 } //1
		$a_01_1 = {6a 04 58 c1 e0 00 8b 84 05 94 fb ff ff 40 6a 04 59 c1 e1 00 89 84 0d 94 fb ff ff 6a 04 58 c1 e0 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
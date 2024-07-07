
rule Trojan_Win32_SDBot_PABJ_MTB{
	meta:
		description = "Trojan:Win32/SDBot.PABJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 ad fc ff ff ff ab b6 72 6b 8b 1f 81 b5 f4 ff ff ff d2 99 ef 9b 03 de 81 b5 fc ff ff ff 9c ca d8 7a 89 1a 81 ad f0 ff ff ff a0 74 70 6e 81 c2 26 69 cf 77 81 c2 de 96 30 88 81 c7 04 00 00 00 e2 be } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
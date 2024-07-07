
rule Trojan_Win32_SDBot_PABM_MTB{
	meta:
		description = "Trojan:Win32/SDBot.PABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 17 81 b5 ec ff ff ff 0c 1c 7f e5 03 d3 29 9d e0 ff ff ff 89 16 31 95 c8 ff ff ff 81 c6 04 00 00 00 81 c7 28 d2 bb e7 81 ef 24 d2 bb e7 e2 d0 } //5
		$a_01_1 = {01 95 f0 ff ff ff 8b 3a 01 85 f4 ff ff ff 2b fb 01 bd f4 ff ff ff 89 3e 29 9d fc ff ff ff 81 c6 04 00 00 00 81 c2 04 00 00 00 e2 d4 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}
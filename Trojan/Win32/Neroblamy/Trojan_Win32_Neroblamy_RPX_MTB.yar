
rule Trojan_Win32_Neroblamy_RPX_MTB{
	meta:
		description = "Trojan:Win32/Neroblamy.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 68 7d d4 00 00 58 40 c1 e8 d6 68 51 d7 00 00 58 2d 13 a1 0d 00 c1 f8 52 58 } //1
		$a_01_1 = {83 65 80 00 8b 45 f4 89 85 4c ff ff ff 8b 45 f8 89 85 54 ff ff ff 83 7d f4 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
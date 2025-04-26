
rule Trojan_Win32_Lokibot_DFGH_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.DFGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {b1 d5 b7 29 ac e2 c6 29 bf b8 ce 25 d3 a6 dc 21 c5 9e d5 1e c7 ac e4 30 c5 a9 dd 25 d2 a9 e1 32 a6 bb c3 26 b1 bd } //1
		$a_01_1 = {e4 3f 46 00 cc 3f 46 00 b0 3f 46 00 a0 3f 46 00 84 3f 46 00 70 3f 46 00 54 3f 46 00 40 3f 46 00 2c 3f 46 00 18 3f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
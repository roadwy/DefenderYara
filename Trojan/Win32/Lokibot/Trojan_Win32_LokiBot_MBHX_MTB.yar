
rule Trojan_Win32_LokiBot_MBHX_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.MBHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {e4 70 ce 32 20 d0 35 90 01 04 d3 e0 b4 79 ef 9e 09 f6 6c 90 00 } //01 00 
		$a_01_1 = {18 3f 40 00 33 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 05 00 00 00 e9 00 00 00 a4 3b 40 00 00 34 40 00 18 33 40 00 78 00 00 00 84 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_LokiBot_ZZ_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.ZZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 74 a4 ac 58 b1 19 2f d4 c8 30 66 50 30 77 d5 } //00 00 
	condition:
		any of ($a_*)
 
}
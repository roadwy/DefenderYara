
rule Trojan_Win32_LokiBot_RPZ_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 89 45 f0 [0-05] 8b 45 08 03 45 f0 8a 00 88 45 f7 [0-05] 8a 45 f7 34 20 8b 55 08 03 55 f0 88 02 [0-05] ff 45 f8 81 7d f8 [0-05] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
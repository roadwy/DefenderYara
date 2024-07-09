
rule Trojan_Win32_LokiBot_RPT_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 ?? ?? ?? ?? 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_RPT_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 2c [0-10] 02 c1 [0-10] f6 d8 [0-10] f6 d0 [0-10] 32 c1 [0-10] 02 c1 [0-10] f6 d8 [0-10] 32 c1 f6 d8 88 04 0e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_RPT_MTB_3{
	meta:
		description = "Trojan:Win32/LokiBot.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 c8 80 f1 7b b2 5c 2a d1 32 d0 b1 12 2a ca c0 c9 02 2a c8 88 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
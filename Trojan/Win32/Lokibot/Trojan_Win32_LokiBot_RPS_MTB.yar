
rule Trojan_Win32_LokiBot_RPS_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 83 e0 03 83 c6 05 8a 44 05 fc 30 82 ?? ?? ?? ?? 83 c2 05 81 fa 05 5a 00 00 72 a9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
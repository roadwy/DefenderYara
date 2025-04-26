
rule Trojan_Win32_MysticStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d3 80 2c 3e 70 ff d3 80 04 3e d6 ff d3 80 34 3e a3 ff d3 80 04 3e 77 ff d3 80 04 3e 5b ff d3 80 04 3e 60 ff d3 80 04 3e f6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
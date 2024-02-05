
rule Trojan_Win32_TrickBot_DSL_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 45 89 8a 4d 88 8a 55 89 c0 e8 04 c0 e1 02 0a c1 8a 4d 8a 88 06 8a c1 c0 e8 02 c0 e2 04 0a c2 46 c0 e1 06 0a 4d 8b 88 06 46 88 0e } //00 00 
	condition:
		any of ($a_*)
 
}
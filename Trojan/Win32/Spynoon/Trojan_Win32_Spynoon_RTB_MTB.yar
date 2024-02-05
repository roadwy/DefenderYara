
rule Trojan_Win32_Spynoon_RTB_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RTB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e3 de d1 00 00 5b 81 ea 19 f5 00 00 41 35 82 18 00 00 43 81 f9 c2 b4 00 00 74 } //00 00 
	condition:
		any of ($a_*)
 
}
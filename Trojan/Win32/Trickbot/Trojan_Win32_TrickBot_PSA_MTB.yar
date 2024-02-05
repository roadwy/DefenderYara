
rule Trojan_Win32_TrickBot_PSA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.PSA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c6 33 d2 b9 2b 00 00 00 f7 f1 8a 04 3e 8a 14 2a 32 c2 88 04 3e 46 3b f3 75 db } //00 00 
	condition:
		any of ($a_*)
 
}
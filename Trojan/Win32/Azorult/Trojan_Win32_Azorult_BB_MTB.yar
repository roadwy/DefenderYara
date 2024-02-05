
rule Trojan_Win32_Azorult_BB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d } //0a 00 
		$a_01_1 = {c3 c1 e0 04 89 01 c3 33 44 24 04 c2 04 00 81 00 } //00 00 
	condition:
		any of ($a_*)
 
}
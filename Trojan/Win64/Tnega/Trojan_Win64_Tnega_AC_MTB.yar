
rule Trojan_Win64_Tnega_AC_MTB{
	meta:
		description = "Trojan:Win64/Tnega.AC!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {e9 c6 00 00 00 e9 72 01 00 00 4d 31 0e e9 cb 00 00 00 e9 11 01 } //0a 00 
		$a_01_1 = {4d 6b c9 00 eb 04 eb d8 eb 2a 4d 69 c9 2f df eb 5a eb 69 } //00 00 
	condition:
		any of ($a_*)
 
}
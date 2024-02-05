
rule Trojan_Win32_Gandcrab_RLQ_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.RLQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 49 ff ff ff 30 04 3e 46 3b f3 7c e1 } //01 00 
		$a_01_1 = {33 c4 89 84 24 00 04 00 00 a1 78 11 41 00 69 c0 fd 43 03 00 8d 0c 24 51 05 c3 9e 26 00 } //00 00 
	condition:
		any of ($a_*)
 
}
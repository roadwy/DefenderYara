
rule Trojan_Win32_Emotet_DHX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 5d fc 03 da 23 d8 8a 54 99 08 8b 5d 08 32 57 01 88 56 01 } //01 00 
		$a_01_1 = {8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 8a 4a 01 42 84 c9 75 e1 } //00 00 
	condition:
		any of ($a_*)
 
}
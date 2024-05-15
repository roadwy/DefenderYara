
rule Trojan_Win64_Zusy_RX_MTB{
	meta:
		description = "Trojan:Win64/Zusy.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 ca 49 8b c0 80 e1 07 c0 e1 03 48 d3 e8 42 30 04 0a 48 ff c2 48 81 fa 0b 27 00 00 72 e1 } //00 00 
	condition:
		any of ($a_*)
 
}
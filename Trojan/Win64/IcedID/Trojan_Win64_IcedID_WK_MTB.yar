
rule Trojan_Win64_IcedID_WK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.WK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8b c1 b9 04 00 00 00 48 f7 f1 48 8b c2 0f b6 44 04 7c 8b 4c 24 64 33 c8 8b c1 48 63 4c 24 40 88 84 0c } //00 00 
	condition:
		any of ($a_*)
 
}
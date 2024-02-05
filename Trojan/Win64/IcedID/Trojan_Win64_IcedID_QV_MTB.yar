
rule Trojan_Win64_IcedID_QV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 40 b9 3b 01 00 00 2b c8 8b 45 40 2b c8 83 c1 46 89 4d 40 8a 45 48 41 88 00 44 89 5d 40 89 5d 48 8b 45 40 8b 45 40 41 23 c6 3b c7 8b 45 40 } //00 00 
	condition:
		any of ($a_*)
 
}
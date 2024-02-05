
rule Trojan_Win64_Emotet_BF_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c2 41 83 c3 90 01 01 c1 e8 90 01 01 03 d0 8d 04 d2 c1 e0 90 01 01 2b c8 48 8b 05 90 01 04 83 c1 90 01 01 48 63 c9 0f b6 0c 01 42 32 4c 16 90 01 01 41 88 4a 90 01 01 49 ff ce 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
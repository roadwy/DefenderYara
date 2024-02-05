
rule Trojan_Win64_CobaltStrikePacker_AE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikePacker.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 d8 48 69 f3 90 01 04 48 89 f1 48 c1 e9 3f 48 c1 fe 23 01 ce c1 e6 02 8d 0c f6 29 cb 48 63 cb 42 0f b6 0c 01 32 0c 02 88 0c 07 48 ff c0 8b 8d 90 01 04 48 39 c8 90 13 48 8b 95 90 01 04 48 63 d8 90 00 } //01 00 
		$a_03_1 = {48 89 c2 83 e2 07 0f b6 14 17 32 14 06 41 88 14 04 48 83 c0 01 48 39 c3 75 e6 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
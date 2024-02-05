
rule Trojan_Win64_IcedId_PAC_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 ff c0 f7 ed 03 d5 c1 fa 05 8b c2 c1 e8 1f 03 d0 8b c5 ff c5 6b d2 23 2b c2 48 63 c8 48 8b 84 24 90 02 04 42 0f b6 0c 09 41 32 4c 00 90 01 01 43 88 4c 18 90 01 01 3b ac 24 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
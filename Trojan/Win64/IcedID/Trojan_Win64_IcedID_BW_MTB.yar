
rule Trojan_Win64_IcedID_BW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {41 f7 ec d1 fa 8b c2 c1 e8 1f 03 d0 49 63 c4 41 83 c4 01 48 63 ca 48 6b c9 43 48 03 c8 48 8b 44 24 28 42 0f b6 8c 31 90 02 04 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
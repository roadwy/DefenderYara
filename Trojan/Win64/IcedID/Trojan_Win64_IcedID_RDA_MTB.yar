
rule Trojan_Win64_IcedID_RDA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 c8 bd 1d 00 00 00 41 f7 ea 89 c8 c1 f8 1f 01 ca c1 fa 04 29 c2 89 c8 0f af d5 29 d0 48 63 d0 41 0f b6 14 10 41 32 14 0b 41 88 14 09 48 83 c1 01 48 81 f9 00 34 00 00 75 } //02 00 
		$a_01_1 = {89 c8 41 89 c9 41 f7 eb 41 c1 f9 1f 89 c8 01 ca c1 fa 04 44 29 ca 41 b9 1d 00 00 00 41 0f af d1 29 d0 48 63 d0 41 0f b6 14 10 32 14 0b 41 88 14 0a 48 83 c1 01 48 81 f9 2c 0a 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}
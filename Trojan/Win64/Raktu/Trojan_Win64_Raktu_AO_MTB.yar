
rule Trojan_Win64_Raktu_AO_MTB{
	meta:
		description = "Trojan:Win64/Raktu.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 85 28 4f 04 00 48 98 0f b6 54 05 b0 8b 85 2c 4f 04 00 48 98 0f b6 84 05 f0 4e 04 00 31 c2 8b 85 28 4f 04 00 48 98 88 94 05 50 27 02 00 83 85 2c 4f 04 00 01 83 85 28 4f 04 00 01 8b 85 28 4f 04 00 3d 99 27 02 00 76 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win64_IcedID_DZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7a 75 61 66 73 6e 68 79 62 61 73 6a 66 6b 61 73 6e 68 66 6b } //0a 00  zuafsnhybasjfkasnhfk
		$a_01_1 = {7a 68 62 73 61 66 75 79 61 73 68 66 6a 6b 61 73 6e 6b 73 61 } //01 00  zhbsafuyashfjkasnksa
		$a_03_2 = {f0 00 22 20 0b 02 90 01 02 00 78 05 00 00 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win64_Bumblebee_MBB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 41 8d 81 90 01 04 44 33 c0 89 0d 90 01 04 48 8b 05 90 01 04 44 89 05 90 01 04 31 14 03 48 83 c3 90 01 01 44 8b 05 90 01 04 8b 05 90 01 04 8b 15 90 01 04 05 90 01 04 44 8b 0d 90 01 04 41 2b d0 03 d0 41 81 c0 90 01 04 8b 05 90 01 04 44 03 c2 41 2b c1 89 15 90 01 04 8b 15 90 00 } //01 00 
		$a_01_1 = {69 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}
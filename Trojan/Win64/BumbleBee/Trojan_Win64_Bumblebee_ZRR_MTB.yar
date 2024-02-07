
rule Trojan_Win64_Bumblebee_ZRR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.ZRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c1 49 63 49 90 01 01 c1 ea 90 01 01 41 89 01 49 8b 81 90 01 04 88 14 01 41 ff 41 90 01 01 49 63 49 90 01 01 49 8b 81 90 01 04 44 88 04 01 41 8b 41 90 01 01 41 ff 41 90 01 01 8d 88 90 01 04 33 c8 41 8b 81 90 01 04 41 89 49 90 01 01 41 29 81 90 01 04 49 81 fa 90 01 04 0f 8c 90 00 } //01 00 
		$a_01_1 = {43 6f 6e 64 65 6e 73 65 64 } //00 00  Condensed
	condition:
		any of ($a_*)
 
}
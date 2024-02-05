
rule Trojan_Win64_Bumblebee_YAH_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f af c1 89 83 90 01 04 8b 83 90 01 04 01 43 0c 8b 83 90 01 04 83 e8 0c 31 43 70 48 8b 43 68 0f b6 4b 3c 41 0f b6 14 00 49 83 c0 04 48 8b 83 90 01 04 0f af d1 48 63 4b 40 88 14 01 44 01 53 40 8b 43 70 41 2b c3 09 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
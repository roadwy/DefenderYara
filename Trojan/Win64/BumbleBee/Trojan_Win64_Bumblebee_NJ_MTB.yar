
rule Trojan_Win64_Bumblebee_NJ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 0b cb 39 88 90 01 04 76 90 01 01 41 8d 81 90 01 04 41 31 80 90 01 04 41 8d 89 90 01 04 23 0d 90 01 04 41 8b 40 90 01 01 0f af c1 41 89 40 90 01 01 41 8d 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
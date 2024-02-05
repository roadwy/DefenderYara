
rule Trojan_Win64_Bumblebee_IRZ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.IRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 04 31 48 83 c6 90 01 01 8b 43 90 01 01 2d 90 01 04 01 43 90 01 01 8b 83 90 01 04 2b 83 90 01 04 8b 53 90 01 01 35 90 01 04 01 83 90 01 04 81 c2 90 01 04 03 53 90 01 01 09 93 90 01 04 8b 83 90 01 04 2b 83 90 01 04 31 43 90 01 01 8b 83 90 01 04 ff c8 01 83 90 01 04 8b 83 90 01 04 01 43 90 01 01 48 81 fe 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
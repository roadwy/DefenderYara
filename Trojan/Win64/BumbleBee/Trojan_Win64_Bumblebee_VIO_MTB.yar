
rule Trojan_Win64_Bumblebee_VIO_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 0f af cd 48 01 8a 90 01 04 48 8b cb 48 8b 97 90 01 04 48 0f af cb 48 8b 82 90 01 04 48 0f af c1 48 89 82 90 01 04 eb 4b 48 8b 87 90 01 04 48 81 b0 90 01 08 48 8b 87 c8 02 00 00 48 c7 80 90 01 08 48 63 87 28 05 00 00 3d 00 0e 24 00 7d 16 48 8b 8f 90 01 04 48 8b d0 41 8a 00 88 04 0a ff 87 90 01 04 49 ff c8 4c 3b 87 90 01 04 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win64_Bumblebee_VIN_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 03 d5 48 8b 4f 90 01 01 48 8b 47 90 01 01 8a 14 0a 41 32 14 01 48 8b 87 90 01 04 41 88 14 01 33 d2 48 63 8f 90 01 04 4c 03 cd 4c 8b 87 a8 02 00 00 48 81 c1 86 d6 ff ff 49 8b 80 90 01 04 48 03 c1 48 63 4f 90 01 01 48 f7 f1 89 97 08 05 00 00 49 81 80 90 01 08 48 8b 87 a8 02 00 00 48 8b 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
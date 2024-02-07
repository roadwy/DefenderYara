
rule Trojan_Win64_Cobaltstrike_ACS_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.ACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {49 63 c8 48 8d 54 24 40 48 03 d1 0f b6 0a 41 88 09 44 88 12 41 0f b6 11 49 03 d2 0f b6 ca 0f b6 54 0c 40 41 30 13 49 ff c3 48 83 eb 01 75 97 } //05 00 
		$a_01_1 = {49 63 c0 48 8d 4d 80 48 03 c8 0f b6 01 41 88 04 31 44 88 11 41 0f b6 0c 31 49 03 ca 0f b6 c1 0f b6 4c 05 80 30 4c 1c 2b 48 83 c3 0c 48 83 fb 54 0f 8c } //01 00 
		$a_01_2 = {63 64 30 39 35 31 39 33 33 38 39 32 65 36 38 38 66 } //01 00  cd0951933892e688f
		$a_01_3 = {33 65 64 31 36 63 64 62 39 31 32 64 37 66 34 33 35 } //00 00  3ed16cdb912d7f435
	condition:
		any of ($a_*)
 
}
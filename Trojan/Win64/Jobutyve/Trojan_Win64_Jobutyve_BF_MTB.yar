
rule Trojan_Win64_Jobutyve_BF_MTB{
	meta:
		description = "Trojan:Win64/Jobutyve.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 44 24 3c 89 c1 83 e1 6c 81 c9 83 00 00 00 25 93 00 00 00 31 c8 34 fb 48 8b 4c 24 50 88 01 8b 44 24 34 ff c0 89 44 24 64 8b 05 90 02 04 8d 48 ff 0f af c8 f6 c1 01 b8 fb b6 06 e1 b9 99 6f fa 91 0f 44 c1 83 3d 90 02 04 0a 0f 4c c1 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
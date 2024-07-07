
rule Trojan_Win64_CobaltStrike_MD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 0c 0f 4c 8d 15 8c d6 03 00 47 0f b6 1c 02 47 0f b6 14 11 41 80 fb 0f 77 90 01 01 41 80 fa 0f 77 90 01 01 41 c1 e3 04 45 09 d3 48 39 d3 77 90 00 } //1
		$a_03_1 = {48 89 84 24 80 00 00 00 48 c7 40 08 12 00 00 00 48 8d 0d a0 08 02 00 48 89 08 90 01 01 48 8d 05 11 59 01 00 e8 90 01 04 83 3d 25 63 12 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_MD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 08 88 14 01 ff 05 90 01 04 48 63 4b 7c 48 8b 83 c8 00 00 00 44 88 0c 01 ff 43 7c 8b 05 90 01 04 8b 8b 94 00 00 00 05 4e 0b fb 28 03 0d 90 01 04 03 c8 89 0d 90 01 04 49 81 fa 30 44 04 00 0f 8c 90 00 } //5
		$a_03_1 = {33 83 98 00 00 00 83 e8 06 01 81 94 00 00 00 8b 83 a8 00 00 00 48 8b 15 90 01 04 2d 05 d4 09 00 31 05 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
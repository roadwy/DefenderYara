
rule Trojan_Win64_CobaltStrike_SP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b d0 c1 ea 08 88 14 01 90 02 70 41 03 c2 09 43 90 01 01 89 8b 90 01 01 00 00 00 8d 81 90 01 04 09 43 90 01 01 49 81 f9 90 01 03 00 0f 8c 90 01 01 ff ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_SP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 d9 66 90 01 04 75 90 01 01 e8 90 01 04 41 90 01 02 ff c6 49 90 01 03 4d 90 01 02 41 90 00 } //1
		$a_03_1 = {39 c3 7e 1b 48 90 01 02 48 90 01 04 83 e2 90 01 01 41 90 01 04 32 14 07 88 14 01 48 90 01 02 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_SP_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {30 5a 4e 41 33 45 5a 34 67 2e 65 78 65 } //1 0ZNA3EZ4g.exe
		$a_81_1 = {30 5a 4e 41 33 45 5a 34 67 2e 78 6c 73 78 } //1 0ZNA3EZ4g.xlsx
		$a_81_2 = {35 30 64 6c 78 4a 65 } //1 50dlxJe
		$a_01_3 = {77 00 69 00 6e 00 72 00 61 00 72 00 73 00 66 00 78 00 6d 00 61 00 70 00 70 00 69 00 6e 00 67 00 66 00 69 00 6c 00 65 00 2e 00 74 00 6d 00 70 00 } //1 winrarsfxmappingfile.tmp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_CobaltStrike_SP_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 46 88 44 0c 40 41 8b c0 4d 8d 49 01 f7 f7 41 ff c0 0f b6 44 14 30 42 88 84 0c 3f 01 00 00 41 81 f8 00 01 00 00 7c d7 } //4
		$a_01_1 = {0f b6 84 14 40 01 00 00 44 0f b6 44 14 40 03 d8 41 03 d8 81 e3 ff 00 00 80 7d 0a ff cb 81 cb 00 ff ff ff ff c3 48 63 c3 48 8d 4c 24 40 48 03 c8 0f b6 01 88 44 14 40 48 ff c2 44 88 01 49 83 e9 01 75 bd } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}
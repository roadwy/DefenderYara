
rule Trojan_Win64_CobaltStrike_BO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 84 c0 74 2a 8b 45 fc 8d 50 01 89 55 fc 89 c2 48 8b 45 10 48 01 d0 0f b7 00 66 89 45 f6 0f b7 55 f6 8b 45 f8 c1 c8 08 01 d0 31 45 f8 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_BO_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 1f e8 90 01 04 33 d2 48 98 48 2b f5 48 f7 f6 49 8b 07 fe c2 41 32 14 06 42 88 14 33 48 8b 0f 46 30 24 31 49 ff c6 49 8b 77 90 01 01 49 8b 2f 48 8b ce 48 2b cd 4c 3b f1 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BO_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 72 69 74 65 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 6d 65 6d 6f 72 79 20 73 75 63 63 65 65 64 65 64 } //1 Write shellcode to memory succeeded
		$a_00_1 = {4d 65 6d 6f 72 79 20 70 65 72 6d 69 73 73 69 6f 6e 73 20 63 68 61 6e 67 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 3a 20 50 41 47 45 5f 45 58 45 43 55 54 45 } //1 Memory permissions changed successfully: PAGE_EXECUTE
		$a_00_2 = {54 68 72 65 61 64 20 6f 70 65 6e 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Thread opened successfully
		$a_03_3 = {48 01 c8 88 10 8b 85 90 01 04 89 c2 8b 85 90 01 04 88 54 05 90 01 01 83 85 90 01 04 01 eb 90 0a 40 00 8b 95 90 01 04 8b 8d 90 01 04 48 8b 85 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
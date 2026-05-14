
rule Trojan_Win64_Amadey_CI_MTB{
	meta:
		description = "Trojan:Win64/Amadey.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d 2f 70 72 6f 66 69 6c 65 73 2f 37 36 35 36 31 31 39 39 38 37 32 36 32 38 36 32 33 2f } //2 https://steamcommunity.com/profiles/76561199872628623/
		$a_01_1 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 } //2 Mozilla/5.0
		$a_01_2 = {6d 73 65 64 67 65 5f 65 6c 66 2e 70 64 62 } //2 msedge_elf.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
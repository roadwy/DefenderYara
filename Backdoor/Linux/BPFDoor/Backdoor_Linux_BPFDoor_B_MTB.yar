
rule Backdoor_Linux_BPFDoor_B_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 85 c4 fd ff ff 8d 50 0e 8b 45 90 01 01 8d 04 02 89 45 90 01 01 8b 45 90 01 01 0f b6 40 0c 0f b6 c0 25 f0 00 00 00 c1 f8 04 c1 e0 02 89 45 90 01 01 8d 85 c4 fd ff ff 8d 50 0e 8b 45 90 01 01 01 c2 8b 45 90 01 01 8d 04 02 89 45 90 00 } //1
		$a_03_1 = {83 c0 14 89 45 90 01 01 8b 45 90 01 01 83 c0 08 89 45 90 01 01 eb 12 8b 45 90 01 01 83 c0 14 89 45 90 01 01 8b 45 90 01 01 83 c0 08 89 45 90 00 } //1
		$a_00_2 = {55 89 e5 83 ec 18 c7 45 f0 3c 08 0a 49 c7 45 f4 00 00 00 00 c7 45 f8 3c 08 0a 49 c7 45 fc 00 00 00 00 8d 45 f0 89 44 24 04 8b 45 08 89 04 24 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
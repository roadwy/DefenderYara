
rule Backdoor_Linux_BPFDoor_C_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 63 6d 70 63 6d 64 } //1 icmpcmd
		$a_00_1 = {75 64 70 63 6d 64 } //1 udpcmd
		$a_00_2 = {67 65 74 70 61 73 73 77 } //1 getpassw
		$a_03_3 = {ff fe ff 48 89 45 ?? 48 8b 45 ?? c6 00 08 48 8b 45 ?? c6 40 01 00 48 8b 45 ?? 66 c7 40 02 00 00 48 8b 45 ?? 66 c7 40 06 d2 04 e8 [0-05] 89 c2 48 8b 45 ?? 66 89 50 04 8b 45 [0-05] 48 8d ?? ?? ff fe ff 48 ?? ?? 08 48 89 ?? be ?? 46 60 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}
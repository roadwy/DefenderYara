
rule Backdoor_Linux_Gyfgyt_BO_MTB{
	meta:
		description = "Backdoor:Linux/Gyfgyt.BO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 64 70 5f 66 6c 6f 6f 64 } //1 udp_flood
		$a_01_1 = {73 74 64 5f 66 6c 6f 6f 64 } //1 std_flood
		$a_01_2 = {68 65 78 5f 66 6c 6f 6f 64 } //1 hex_flood
		$a_01_3 = {70 72 6f 63 65 73 73 43 6d 64 } //1 processCmd
		$a_01_4 = {6d 79 66 72 69 65 6e 64 77 68 6f 73 6e 61 6d 65 69 73 6e 6f 6f 64 6c 65 73 69 73 61 66 65 67 67 65 74 } //1 myfriendwhosnameisnoodlesisafegget
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}

rule Backdoor_Linux_Bossabot_B_xp{
	meta:
		description = "Backdoor:Linux/Bossabot.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 63 61 6e 72 6e 64 } //1 scanrnd
		$a_00_1 = {72 6d 20 2d 72 20 2f 74 6d 70 2f 70 6f 6f 6c } //1 rm -r /tmp/pool
		$a_00_2 = {4e 4f 54 49 43 45 20 25 73 20 3a 52 65 6d 6f 76 65 64 20 61 6c 6c 20 73 70 6f 6f 66 73 } //1 NOTICE %s :Removed all spoofs
		$a_00_3 = {70 6b 69 6c 6c 20 6d 69 6e 65 72 64 } //1 pkill minerd
		$a_00_4 = {42 6f 53 53 61 42 6f 54 76 32 2d 25 73 } //1 BoSSaBoTv2-%s
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
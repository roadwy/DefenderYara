
rule Backdoor_Linux_Bossabot_A_xp{
	meta:
		description = "Backdoor:Linux/Bossabot.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 43 41 4e 52 4e 44 32 } //2 SCANRND2
		$a_01_1 = {2f 74 6d 70 2f 52 65 56 31 31 31 32 } //1 /tmp/ReV1112
		$a_01_2 = {4e 4f 54 49 43 45 20 25 73 20 3a 53 44 } //1 NOTICE %s :SD
		$a_01_3 = {24 77 6f 70 20 3d 20 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 77 6f 70 29 } //1 $wop = base64_decode($wop)
		$a_01_4 = {4e 4f 54 49 43 45 20 25 73 20 3a 72 6e 64 32 20 25 73 20 74 20 25 73 20 74 20 25 73 } //1 NOTICE %s :rnd2 %s t %s t %s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
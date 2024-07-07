
rule Backdoor_Linux_Sonyn_A_xp{
	meta:
		description = "Backdoor:Linux/Sonyn.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 6d 6f 64 20 2b 78 20 75 70 64 61 74 65 2e 73 68 } //1 chmod +x update.sh
		$a_01_1 = {74 61 72 20 63 76 7a 66 20 2f 74 6d 70 2f 64 6f 63 2e 74 61 72 2e 67 7a } //1 tar cvzf /tmp/doc.tar.gz
		$a_01_2 = {31 30 30 30 3a 2f 6c 6f 6f 74 } //1 1000:/loot
		$a_01_3 = {2e 2f 65 78 65 63 2e 73 68 } //1 ./exec.sh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
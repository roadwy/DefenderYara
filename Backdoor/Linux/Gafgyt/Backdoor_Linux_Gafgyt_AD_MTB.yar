
rule Backdoor_Linux_Gafgyt_AD_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 64 6f 73 63 6d 64 73 } //01 00  ddoscmds
		$a_01_1 = {62 6f 74 63 6f 75 6e 74 } //01 00  botcount
		$a_01_2 = {73 65 72 76 65 72 63 6d 64 73 } //01 00  servercmds
		$a_01_3 = {68 62 6f 74 2e 62 6f 74 6b 69 6c 6c } //01 00  hbot.botkill
		$a_01_4 = {6b 69 6c 6c 65 72 2e 74 78 74 } //01 00  killer.txt
		$a_01_5 = {6b 69 63 6b 75 73 65 72 } //00 00  kickuser
	condition:
		any of ($a_*)
 
}
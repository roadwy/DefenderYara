
rule Backdoor_Linux_Gafgyt_BW_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BW!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 72 75 67 61 6d 69 } //01 00  Sarugami
		$a_01_1 = {62 6f 74 6b 69 6c 6c } //01 00  botkill
		$a_01_2 = {75 64 70 00 2f 64 65 76 2f 6e 75 6c 6c 90 00 } //01 00 
		$a_01_3 = {50 4f 4e 47 } //01 00  PONG
		$a_01_4 = {50 49 4e 47 } //00 00  PING
	condition:
		any of ($a_*)
 
}
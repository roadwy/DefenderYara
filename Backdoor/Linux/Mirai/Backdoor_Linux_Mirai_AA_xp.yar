
rule Backdoor_Linux_Mirai_AA_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AA!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 77 64 2f 6f 6e 75 50 72 6f 62 65 } //01 00  /tmp/wd/onuProbe
		$a_01_1 = {2f 68 6f 6d 65 2f 68 69 6b 2f 68 69 63 6f 72 65 } //01 00  /home/hik/hicore
		$a_01_2 = {74 63 70 2d 70 6c 61 69 6e } //01 00  tcp-plain
		$a_01_3 = {6b 69 6c 6c 65 72 5f 69 6e 69 74 } //01 00  killer_init
		$a_01_4 = {65 78 65 5f 6b 69 6c 6c } //00 00  exe_kill
	condition:
		any of ($a_*)
 
}
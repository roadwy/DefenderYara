
rule Backdoor_Linux_Tsunami_F_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5b 55 44 50 5d 20 41 74 74 61 63 6b 69 6e 67 } //01 00  [UDP] Attacking
		$a_00_1 = {50 52 49 56 4d 53 47 20 25 73 20 3a 4b 69 6c 6c 69 6e 67 20 50 49 44 20 } //02 00  PRIVMSG %s :Killing PID 
		$a_00_2 = {2b 62 6f 74 6b 69 6c 6c } //02 00  +botkill
		$a_00_3 = {52 65 6d 6f 74 65 20 49 52 43 20 42 6f 74 } //00 00  Remote IRC Bot
	condition:
		any of ($a_*)
 
}
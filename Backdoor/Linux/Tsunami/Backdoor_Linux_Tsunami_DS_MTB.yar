
rule Backdoor_Linux_Tsunami_DS_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.DS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {49 27 6d 20 68 61 76 69 6e 67 20 61 20 70 72 6f 62 6c 65 6d 20 72 65 73 6f 6c 76 69 6e 67 20 6d 79 20 68 6f 73 74 2c 20 73 6f 6d 65 6f 6e 65 20 77 69 6c 6c 20 68 61 76 65 20 74 6f 20 53 50 4f 4f 46 53 20 6d 65 20 6d 61 6e 75 61 6c 6c 79 } //1 I'm having a problem resolving my host, someone will have to SPOOFS me manually
		$a_00_1 = {4b 69 6c 6c 69 6e 67 20 70 69 64 20 25 64 } //1 Killing pid %d
		$a_00_2 = {50 52 49 56 4d 53 47 20 25 73 20 3a 3e 62 6f 74 20 2b 75 6e 6b 6e 6f 77 6e 20 3c 74 61 72 67 65 74 3e 20 3c 73 65 63 73 3e } //2 PRIVMSG %s :>bot +unknown <target> <secs>
		$a_00_3 = {52 65 6d 6f 74 65 20 49 52 43 20 42 6f 74 } //1 Remote IRC Bot
		$a_00_4 = {52 41 57 2d 55 44 50 20 46 6c 6f 6f 64 69 6e 67 } //1 RAW-UDP Flooding
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
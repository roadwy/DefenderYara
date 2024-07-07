
rule Backdoor_Linux_Gafgyt_DB_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.DB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6b 69 6c 6c 20 2d 66 20 63 6f 6e 64 69 } //1 pkill -f condi
		$a_01_1 = {75 64 70 2d 70 6c 61 69 6e } //1 udp-plain
		$a_01_2 = {62 69 6c 6c 79 62 6f 62 62 6f 74 2e 63 6f 6d 2f 63 72 61 77 6c 65 72 } //1 billybobbot.com/crawler
		$a_01_3 = {69 63 6d 70 2d 70 6c 61 69 6e } //1 icmp-plain
		$a_01_4 = {2e 2f 63 6f 6e 64 69 2e 6d 69 70 73 } //1 ./condi.mips
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
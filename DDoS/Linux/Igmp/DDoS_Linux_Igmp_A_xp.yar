
rule DDoS_Linux_Igmp_A_xp{
	meta:
		description = "DDoS:Linux/Igmp.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 70 6f 6f 66 69 6e 67 20 61 74 74 61 63 6b } //2 spoofing attack
		$a_01_1 = {3c 67 6f 74 20 72 6f 6f 74 } //1 <got root
		$a_01_2 = {69 67 6d 70 2d 38 2b 66 72 61 67 20 61 74 74 61 63 6b 73 } //1 igmp-8+frag attacks
		$a_01_3 = {3c 73 70 6f 6f 66 20 68 6f 73 74 3e 20 3c 74 61 72 67 65 74 20 68 6f 73 74 3e 20 3c 6e 75 6d 62 65 72 3e } //1 <spoof host> <target host> <number>
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
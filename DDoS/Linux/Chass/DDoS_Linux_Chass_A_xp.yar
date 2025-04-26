
rule DDoS_Linux_Chass_A_xp{
	meta:
		description = "DDoS:Linux/Chass.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 65 67 69 6e 6e 69 6e 67 20 61 74 74 61 63 6b 20 6f 6e 20 63 68 61 73 73 69 73 20 25 73 20 5b 25 64 20 70 61 63 6b 65 74 73 5d } //2 Beginning attack on chassis %s [%d packets]
		$a_01_1 = {41 74 74 61 63 6b 20 63 6f 6d 70 6c 65 74 65 2e } //1 Attack complete.
		$a_01_2 = {53 79 6e 74 61 78 3a 20 25 73 20 3c 63 68 61 73 73 69 73 20 6e 61 6d 65 3e 20 3c 6e 75 6d 20 6f 66 20 70 61 63 6b 65 74 73 3e } //1 Syntax: %s <chassis name> <num of packets>
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}

rule DDoS_Linux_Flushot_A_xp{
	meta:
		description = "DDoS:Linux/Flushot.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 6d 6f 74 65 20 46 6c 75 73 68 6f 74 } //2 Remote Flushot
		$a_01_1 = {54 68 65 20 46 6c 75 20 48 61 63 6b 69 6e 67 20 47 72 6f 75 70 } //2 The Flu Hacking Group
		$a_01_2 = {75 73 61 67 65 3a 2e 2f 66 6c 75 73 68 6f 74 20 5b 53 70 6f 6f 66 65 64 20 49 50 5d 20 5b 44 65 73 74 69 6e 61 74 69 6f 6e 20 49 50 5d 20 5b 6f 66 20 46 4c 75 73 68 6f 74 20 74 6f 20 53 65 6e 64 5d } //2 usage:./flushot [Spoofed IP] [Destination IP] [of FLushot to Send]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}
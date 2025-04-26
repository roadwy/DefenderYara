
rule HackTool_Linux_Quacker_A_xp{
	meta:
		description = "HackTool:Linux/Quacker.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 2e 2f 73 6d 61 63 6b 20 3c 74 61 72 67 65 74 20 74 6f 20 66 75 63 6b 3e } //2 Usage: ./smack <target to fuck>
		$a_01_1 = {53 6c 69 6e 67 69 6e 67 20 50 61 63 6b 65 74 73 } //1 Slinging Packets
		$a_01_2 = {53 6e 6f 6f 70 79 } //1 Snoopy
		$a_01_3 = {73 6d 61 63 6b 2e 63 } //1 smack.c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
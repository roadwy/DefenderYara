
rule Backdoor_Linux_Tsunami_I_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.I!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 52 43 20 42 6f 74 } //2 IRC Bot
		$a_01_1 = {50 61 63 6b 65 74 42 4f 54 } //1 PacketBOT
		$a_01_2 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 2e 6c 6f 63 61 6c } //1 /etc/rc.d/rc.local
		$a_01_3 = {62 6f 74 20 2b 73 74 64 20 3c 74 61 72 67 65 74 3e 20 3c 70 6f 72 74 3e 20 3c 73 65 63 73 3e } //2 bot +std <target> <port> <secs>
		$a_01_4 = {4b 69 6c 6c 69 6e 67 20 70 69 64 20 25 64 } //2 Killing pid %d
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=5
 
}
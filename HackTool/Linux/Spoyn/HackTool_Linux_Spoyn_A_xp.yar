
rule HackTool_Linux_Spoyn_A_xp{
	meta:
		description = "HackTool:Linux/Spoyn.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 6f 6f 66 65 64 20 53 59 4e 20 41 74 74 61 63 6b } //01 00  Spoofed SYN Attack
		$a_01_1 = {5b 78 5d 20 45 72 72 6f 72 20 73 65 6e 64 69 6e 67 20 70 61 63 6b 65 74 } //01 00  [x] Error sending packet
		$a_01_2 = {55 73 61 67 65 3a 20 25 73 20 3c 53 61 6c 64 69 72 69 6c 61 63 61 6b 20 49 50 3e 20 3c 50 4f 52 54 3e 20 3c 53 55 52 45 3e } //00 00  Usage: %s <Saldirilacak IP> <PORT> <SURE>
	condition:
		any of ($a_*)
 
}
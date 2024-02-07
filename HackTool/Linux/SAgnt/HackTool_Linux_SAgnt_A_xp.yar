
rule HackTool_Linux_SAgnt_A_xp{
	meta:
		description = "HackTool:Linux/SAgnt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 73 79 73 6c 6f 67 64 20 6b 69 6c 6c 65 64 } //01 00  [*] syslogd killed
		$a_01_1 = {73 79 73 6c 6f 67 64 2f 6e 65 77 73 79 73 6c 6f 67 64 20 61 74 74 61 63 6b } //01 00  syslogd/newsyslogd attack
		$a_01_2 = {25 73 20 2d 69 20 73 74 72 69 6e 67 20 2d 6d 20 2f 76 61 72 2f 6c 6f 67 2f 6d 65 73 73 61 67 65 73 } //01 00  %s -i string -m /var/log/messages
		$a_01_3 = {77 61 72 6e 69 6e 67 20 69 73 20 69 6e 20 50 52 4f 4d 49 53 43 20 4d 4f 44 45 } //01 00  warning is in PROMISC MODE
		$a_01_4 = {69 6d 70 6f 73 73 69 62 6c 65 20 72 65 73 74 61 72 74 20 73 79 73 6c 6f 67 64 } //00 00  impossible restart syslogd
	condition:
		any of ($a_*)
 
}
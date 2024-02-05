
rule Trojan_Linux_Turla_D{
	meta:
		description = "Trojan:Linux/Turla.D,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {4c 6f 67 20 65 6e 64 65 64 20 61 74 20 3d 3e 20 25 73 } //Log ended at => %s  01 00 
		$a_80_1 = {4c 6f 67 20 73 74 61 72 74 65 64 20 61 74 20 3d 3e 20 25 73 20 5b 70 69 64 20 25 64 5d } //Log started at => %s [pid %d]  01 00 
		$a_80_2 = {2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 68 6f 73 74 } ///var/tmp/taskhost  01 00 
		$a_80_3 = {6d 79 20 68 6f 73 74 6e 61 6d 65 3a 20 25 73 } //my hostname: %s  01 00 
		$a_80_4 = {2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 6c 6f 67 } ///var/tmp/tasklog  01 00 
		$a_80_5 = {2f 76 61 72 2f 74 6d 70 2f 2e 58 74 6d 70 30 31 } ///var/tmp/.Xtmp01  01 00 
		$a_80_6 = {6d 79 66 69 6c 65 6e 61 6d 65 3d 2d 25 73 2d } //myfilename=-%s-  01 00 
		$a_80_7 = {2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 70 69 64 } ///var/tmp/taskpid  01 00 
		$a_80_8 = {6d 79 70 69 64 3d 2d 25 64 2d } //mypid=-%d-  01 00 
		$a_80_9 = {2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 67 69 64 } ///var/tmp/taskgid  01 00 
		$a_80_10 = {6d 79 67 69 64 3d 2d 25 64 2d } //mygid=-%d-  00 00 
	condition:
		any of ($a_*)
 
}
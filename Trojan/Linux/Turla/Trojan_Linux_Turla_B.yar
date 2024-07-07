
rule Trojan_Linux_Turla_B{
	meta:
		description = "Trojan:Linux/Turla.B,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 52 52 4f 52 3a 20 55 6e 6c 69 6e 6b 69 6e 67 20 74 6d 70 20 57 54 4d 50 20 66 69 6c 65 2e } //ERROR: Unlinking tmp WTMP file.  1
		$a_80_1 = {55 53 41 47 45 3a 20 77 69 70 65 20 5b 20 75 7c 77 7c 6c 7c 61 20 5d 20 2e 2e 2e 6f 70 74 69 6f 6e 73 2e 2e 2e } //USAGE: wipe [ u|w|l|a ] ...options...  1
		$a_80_2 = {45 72 61 73 65 20 61 63 63 74 20 65 6e 74 72 69 65 73 20 6f 6e 20 74 74 79 20 3a 20 77 69 70 65 20 61 20 5b 75 73 65 72 6e 61 6d 65 5d 20 5b 74 74 79 5d } //Erase acct entries on tty : wipe a [username] [tty]  1
		$a_80_3 = {41 6c 74 65 72 20 6c 61 73 74 6c 6f 67 20 65 6e 74 72 79 20 3a 20 77 69 70 65 20 6c 20 5b 75 73 65 72 6e 61 6d 65 5d 20 5b 74 74 79 5d 20 5b 74 69 6d 65 5d 20 5b 68 6f 73 74 5d } //Alter lastlog entry : wipe l [username] [tty] [time] [host]  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}

rule Backdoor_Linux_Tsunami_G_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 72 63 2e 74 65 61 6d 74 6e 74 2e 72 65 64 } //01 00  irc.teamtnt.red
		$a_00_1 = {74 72 61 70 20 27 27 20 31 3b 73 68 20 2d 63 20 27 6b 69 6c 6c 61 6c 6c 20 6b 61 69 74 65 6e 2a 3b 6b 69 6c 6c 61 6c 6c 20 6b 74 2a 3b 6b 69 6c 6c 61 6c 6c 20 2e 6f 3b 73 6c 65 65 70 20 35 3b 74 72 61 70 } //01 00  trap '' 1;sh -c 'killall kaiten*;killall kt*;killall .o;sleep 5;trap
		$a_00_2 = {48 61 63 6b 50 6b 67 20 69 73 20 68 65 72 65 21 20 49 6e 73 74 61 6c 6c 20 61 20 62 69 6e } //01 00  HackPkg is here! Install a bin
		$a_02_3 = {49 4e 53 54 41 4c 4c 20 90 02 05 2f 2f 73 65 72 76 65 72 2f 73 63 61 6e 20 66 69 72 73 74 90 00 } //01 00 
		$a_00_4 = {4b 69 6c 6c 20 74 65 6c 6e 65 74 2c 20 64 2f 6c 20 61 65 73 20 62 61 63 6b 64 6f 6f 72 20 66 72 6f 6d 20 3c 73 65 72 76 65 72 } //01 00  Kill telnet, d/l aes backdoor from <server
		$a_01_5 = {65 63 68 6f 20 49 79 45 76 59 6d 6c 75 4c 32 4a 68 63 32 67 4b 43 6d 56 34 63 47 39 79 64 43 42 4d 51 31 39 42 54 45 77 39 51 77 6f 4b 53 45 6c 54 56 45 4e 50 54 6c 52 53 54 30 77 39 49 6d 6c 6e 62 6d 39 79 5a 58 4e 77 59 57 4e 6c 4a 48 74 49 53 56 4e 55 51 30 39 4f 56 46 4a 50 54 44 6f 72 4f 69 52 } //00 00  echo IyEvYmluL2Jhc2gKCmV4cG9ydCBMQ19BTEw9QwoKSElTVENPTlRST0w9Imlnbm9yZXNwYWNlJHtISVNUQ09OVFJPTDorOiR
	condition:
		any of ($a_*)
 
}

rule Backdoor_MacOS_NetWired{
	meta:
		description = "Backdoor:MacOS/NetWired,SIGNATURE_TYPE_MACHOHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //2 checkip.dyndns.org
		$a_00_1 = {6d 61 63 68 64 65 70 2e 63 70 75 2e 62 72 61 6e 64 5f 73 74 72 69 6e 67 } //2 machdep.cpu.brand_string
		$a_00_2 = {42 0f b6 d2 0f b6 44 14 08 01 c3 0f b6 db 8a 4c 1c 08 88 4c 14 08 88 44 1c 08 00 c1 0f b6 c1 8a 44 04 08 30 07 47 4e 75 d7 a1 1c e0 00 00 8b 00 3b 84 24 08 01 00 00 75 0b 81 c4 0c 01 00 00 5e 5f 5b 5d c3 } //4
		$a_00_3 = {52 75 6e 41 74 4c 6f 61 64 } //1 RunAtLoad
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f } //1 /Library/LaunchAgents/
		$a_00_5 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 } //1 CONNECT %s:%d HTTP/1.0
		$a_00_6 = {68 79 64 37 75 35 6a 64 69 38 } //1 hyd7u5jdi8
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*4+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=12
 
}
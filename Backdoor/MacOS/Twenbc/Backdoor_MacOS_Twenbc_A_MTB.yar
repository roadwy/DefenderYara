
rule Backdoor_MacOS_Twenbc_A_MTB{
	meta:
		description = "Backdoor:MacOS/Twenbc.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {48 89 f7 48 89 f5 e8 90 01 03 00 4c 8d 64 05 00 48 83 f8 0f 48 89 44 24 08 76 1b 48 8d 74 24 08 31 d2 48 89 df e8 90 01 03 00 48 89 03 48 8b 44 24 08 48 89 43 10 90 00 } //1
		$a_01_1 = {2f 76 61 72 2f 72 75 6e 2f 6c 65 67 61 63 79 5f 61 67 65 6e 74 2e 70 69 64 } //1 /var/run/legacy_agent.pid
		$a_01_2 = {73 77 5f 76 65 72 73 20 7c 20 67 72 65 70 20 22 50 72 6f 64 75 63 74 56 65 72 73 69 6f 6e 22 20 7c 20 74 72 20 2d 64 63 20 27 30 2d 39 2e 27 } //1 sw_vers | grep "ProductVersion" | tr -dc '0-9.'
		$a_01_3 = {33 45 71 7a 77 72 33 59 6a 4a 33 43 36 75 63 51 47 55 4e 72 71 52 4e 74 68 39 59 45 4e 51 66 55 } //1 3Eqzwr3YjJ3C6ucQGUNrqRNth9YENQfU
		$a_01_4 = {55 70 50 27 43 51 42 22 77 48 48 4f 26 61 36 4f 62 75 3c 74 24 61 40 6e } //1 UpP'CQB"wHHO&a6Obu<t$a@n
		$a_01_5 = {6d 61 63 68 64 65 70 2e 63 70 75 2e 62 72 61 6e 64 5f 73 74 72 69 6e 67 } //1 machdep.cpu.brand_string
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
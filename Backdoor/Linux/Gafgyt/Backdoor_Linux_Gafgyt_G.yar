
rule Backdoor_Linux_Gafgyt_G{
	meta:
		description = "Backdoor:Linux/Gafgyt.G,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 07 00 00 "
		
	strings :
		$a_00_0 = {5b 30 6d 20 50 41 53 53 57 4f 52 44 20 53 45 4e 54 20 2d 2d 3e 20 5b 25 73 3a 32 33 7c 25 73 5d } //1 [0m PASSWORD SENT --> [%s:23|%s]
		$a_00_1 = {5b 30 6d 20 55 53 45 52 4e 41 4d 45 20 53 45 4e 54 20 2d 2d 3e 20 5b 25 73 3a 32 33 7c 25 73 5d } //1 [0m USERNAME SENT --> [%s:23|%s]
		$a_00_2 = {5b 30 6d 20 44 45 56 49 43 45 20 46 4f 55 4e 44 20 2d 2d 3e 20 5b 25 73 3a 32 33 } //1 [0m DEVICE FOUND --> [%s:23
		$a_00_3 = {43 6f 63 6b 20 70 75 6c 6c 65 64 20 6f 75 74 20 61 6e 64 20 61 77 61 69 74 69 6e 67 20 6f 72 64 65 72 73 } //1 Cock pulled out and awaiting orders
		$a_00_4 = {5b 30 6d 20 44 69 63 6b 73 69 7a 65 3a 20 25 73 2e } //1 [0m Dicksize: %s.
		$a_00_5 = {55 44 50 20 46 6c 6f 6f 64 20 46 72 6f 6d 20 51 62 6f 74 } //1 UDP Flood From Qbot
		$a_00_6 = {5b 30 6d 20 57 74 66 20 69 73 20 74 68 69 73 20 73 68 69 74 3a 20 25 73 } //1 [0m Wtf is this shit: %s
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=2
 
}
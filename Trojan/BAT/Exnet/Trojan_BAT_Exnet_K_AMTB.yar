
rule Trojan_BAT_Exnet_K_AMTB{
	meta:
		description = "Trojan:BAT/Exnet.K!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_80_0 = {57 4a 6b 4d 44 59 77 4d 47 51 31 5a 57 4d 31 4e 44 4e 68 5a 54 51 34 4d 54 6b 77 4e 6d 46 6d 4f 54 4a 6c 59 6a 42 6d 4e 6a 6b 30 } //WJkMDYwMGQ1ZWM1NDNhZTQ4MTkwNmFmOTJlYjBmNjk0  1
		$a_80_1 = {54 55 35 59 7a 55 77 5a 6a 63 33 4e 44 55 35 5a 44 56 6a 4d 54 41 34 4f 44 63 33 5a 6d 51 78 4d 7a 42 68 4d 54 59 78 5a 44 45 32 4f 57 5a 6d 4d 6d 59 78 4e 44 4e 6b 5a 6d 5a 6c 4f 54 45 30 5a 47 51 78 4d 6d 4a 68 59 7a 63 78 4d 7a 59 30 59 57 5a 6d 4e 6a 55 } //TU5YzUwZjc3NDU5ZDVjMTA4ODc3ZmQxMzBhMTYxZDE2OWZmMmYxNDNkZmZlOTE0ZGQxMmJhYzcxMzY0YWZmNjU  1
		$a_80_2 = {69 6e 6a 65 63 74 65 64 20 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //injected  successfully  1
		$a_80_3 = {6e 67 72 6f 6b 20 69 6e 73 74 61 6c 6c 65 64 } //ngrok installed  1
		$a_80_4 = {43 79 72 65 78 5f 76 69 63 74 69 6d } //Cyrex_victim  1
		$a_80_5 = {47 65 74 20 70 61 73 73 77 6f 72 64 73 20 73 74 61 72 65 64 } //Get passwords stared  1
		$a_80_6 = {72 65 6d 6f 76 65 20 41 56 20 53 74 61 72 74 65 64 } //remove AV Started  1
		$a_80_7 = {72 65 73 74 61 72 74 20 76 69 63 74 69 6d 20 50 43 } //restart victim PC  1
		$a_80_8 = {41 6e 79 44 65 73 6b 20 50 61 73 73 77 6f 72 64 73 } //AnyDesk Passwords  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=8
 
}
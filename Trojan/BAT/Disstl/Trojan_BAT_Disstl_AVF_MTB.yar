
rule Trojan_BAT_Disstl_AVF_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 08 00 00 "
		
	strings :
		$a_80_0 = {69 6e 64 65 78 2e 6a 73 } //index.js  5
		$a_80_1 = {44 69 73 63 6f 72 64 42 75 69 6c 64 } //DiscordBuild  5
		$a_80_2 = {47 65 74 44 69 73 63 6f 72 64 50 61 74 68 } //GetDiscordPath  5
		$a_80_3 = {49 6e 6a 65 63 74 } //Inject  5
		$a_80_4 = {44 69 73 63 6f 72 64 43 61 6e 61 72 79 } //DiscordCanary  4
		$a_80_5 = {42 75 69 6c 64 54 6f 53 74 72 69 6e 67 } //BuildToString  4
		$a_80_6 = {64 69 73 63 6f 72 64 5f 64 65 73 6b 74 6f 70 5f 63 6f 72 65 } //discord_desktop_core  4
		$a_80_7 = {5c 64 2e 5c 64 2e 5c 64 7b 32 7d 28 5c 64 7c 24 29 } //\d.\d.\d{2}(\d|$)  4
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*4+(#a_80_7  & 1)*4) >=36
 
}
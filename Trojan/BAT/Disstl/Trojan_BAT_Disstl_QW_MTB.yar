
rule Trojan_BAT_Disstl_QW_MTB{
	meta:
		description = "Trojan:BAT/Disstl.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {64 69 73 63 6f 72 64 5f 64 65 73 6b 74 6f 70 5f 63 6f 72 65 5c 69 6e 64 65 78 2e 6a 73 } //discord_desktop_core\index.js  3
		$a_80_1 = {44 69 73 63 6f 72 64 50 54 42 } //DiscordPTB  3
		$a_80_2 = {44 69 73 63 6f 72 64 43 61 6e 61 72 79 } //DiscordCanary  3
		$a_80_3 = {77 61 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //wang.Properties.Resources  3
		$a_80_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //GetFolderPath  3
		$a_80_5 = {79 6f 75 72 5f 68 6f 6f 6b } //your_hook  3
		$a_80_6 = {70 72 6f 63 65 73 73 2e 65 6e 76 2e 68 6f 6f 6b } //process.env.hook  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
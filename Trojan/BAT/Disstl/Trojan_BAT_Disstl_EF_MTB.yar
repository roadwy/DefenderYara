
rule Trojan_BAT_Disstl_EF_MTB{
	meta:
		description = "Trojan:BAT/Disstl.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_81_0 = {64 69 73 63 6f 72 64 5f 64 65 73 6b 74 6f 70 5f 63 6f 72 65 5c 69 6e 64 65 78 2e 6a 73 } //3 discord_desktop_core\index.js
		$a_81_1 = {44 69 73 63 6f 72 64 50 54 42 } //3 DiscordPTB
		$a_81_2 = {44 69 73 63 6f 72 64 43 61 6e 61 72 79 } //3 DiscordCanary
		$a_81_3 = {66 69 72 73 74 72 75 6e } //3 firstrun
		$a_81_4 = {68 6f 6f 6b 55 72 6c } //3 hookUrl
		$a_81_5 = {4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 44 69 73 63 6f 72 64 } //3 Local Settings\Application Data\Discord
		$a_81_6 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //3 GetFolderPath
		$a_81_7 = {77 61 6e 67 32 2e 70 64 62 } //3 wang2.pdb
		$a_81_8 = {52 65 70 6c 61 63 65 } //3 Replace
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3) >=27
 
}
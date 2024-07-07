
rule Trojan_BAT_Disstl_ANJ_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 65 6c 65 74 65 4c 6f 63 61 6c 53 74 6f 72 61 67 65 } //DeleteLocalStorage  3
		$a_80_1 = {4b 69 6c 6c 50 72 6f 63 65 73 73 } //KillProcess  3
		$a_80_2 = {64 69 73 63 6f 72 64 5f 64 65 73 6b 74 6f 70 5f 63 6f 72 65 } //discord_desktop_core  3
		$a_80_3 = {44 69 73 63 6f 72 64 46 75 63 6b 65 72 } //DiscordFucker  3
		$a_80_4 = {2f 69 6e 6a 65 63 74 6f 72 2f 70 65 72 6d 61 6e 61 6e 74 3f 77 65 62 68 6f 6f 6b 3d } ///injector/permanant?webhook=  3
		$a_80_5 = {69 6e 64 65 78 2e 6a 73 } //index.js  3
		$a_80_6 = {44 69 73 63 6f 72 64 50 54 42 } //DiscordPTB  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
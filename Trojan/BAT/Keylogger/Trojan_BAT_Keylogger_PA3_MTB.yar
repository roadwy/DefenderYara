
rule Trojan_BAT_Keylogger_PA3_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.PA3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 2e 67 67 2f 75 64 52 68 6d 33 68 59 48 4d } //https://discord.gg/udRhm3hYHM  2
		$a_80_1 = {6b 65 79 6c 6f 67 } //keylog  1
		$a_80_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 62 6f 74 6e 65 74 2e 68 65 6c 70 3b } //SELECT * FROM botnet.help;  1
		$a_80_3 = {50 41 53 53 57 4f 52 44 3d } //PASSWORD=  1
		$a_80_4 = {53 45 52 56 45 52 3d } //SERVER=  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}
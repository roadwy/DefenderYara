
rule Trojan_BAT_Zbot_ET_MTB{
	meta:
		description = "Trojan:BAT/Zbot.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {0a 14 0b 14 0c 0e 04 2c 15 06 03 72 76 28 00 70 04 28 12 00 00 0a 6f 13 00 00 0a 0c 2b 1a 06 03 72 76 28 00 70 04 28 12 00 00 0a 6f 14 00 00 0a 0b 07 6f 15 00 00 0a 0c 08 05 6f 16 00 00 0a 07 0e 05 6f 17 00 00 0a 2a } //10
		$a_80_1 = {66 75 6e 63 74 69 6f 6e 31 } //function1  3
		$a_80_2 = {42 75 69 6c 64 41 73 73 65 6d 62 6c 79 } //BuildAssembly  3
		$a_80_3 = {73 68 65 6c 6c 63 6f 64 65 } //shellcode  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}
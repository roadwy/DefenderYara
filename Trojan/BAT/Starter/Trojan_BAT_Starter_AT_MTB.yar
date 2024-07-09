
rule Trojan_BAT_Starter_AT_MTB{
	meta:
		description = "Trojan:BAT/Starter.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0b de 0a 07 2c 06 07 6f ?? ?? ?? 0a dc 73 05 00 00 0a 0a 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 26 de 03 26 de 00 1f 64 28 ?? ?? ?? 0a 2b a8 } //10
		$a_80_1 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4c 6f 6c 43 6c 69 65 6e 74 5c } //\AppData\Roaming\LolClient\  4
		$a_80_2 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //get_ExecutablePath  3
		$a_80_3 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //ProcessStartInfo  3
		$a_80_4 = {73 65 74 5f 46 69 6c 65 4e 61 6d 65 } //set_FileName  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*4+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=14
 
}
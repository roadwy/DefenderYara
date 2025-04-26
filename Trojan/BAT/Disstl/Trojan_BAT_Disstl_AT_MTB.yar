
rule Trojan_BAT_Disstl_AT_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 07 00 00 "
		
	strings :
		$a_02_0 = {0b 2b 3e 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 6f ?? ?? ?? 0a 16 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 1f 3b 2e 0c 08 6f ?? ?? ?? 0a 1f 58 fe 01 2b 01 17 2c 04 08 0a de 24 07 } //10
		$a_80_1 = {6b 6f 6f 48 20 6e 69 61 74 70 61 43 } //kooH niatpaC  5
		$a_80_2 = {62 64 6c 65 76 65 6c 5c 65 67 61 72 6f 74 53 20 6c 61 63 6f 4c 5c 64 72 6f 63 73 69 64 } //bdlevel\egarotS lacoL\drocsid  5
		$a_80_3 = {28 5b 41 2d 5a 61 2d 7a 30 2d 39 5f 5c 2e 2f 5c 5c 2d 5d 2a 29 } //([A-Za-z0-9_\./\\-]*)  3
		$a_80_4 = {62 64 6c 2e } //bdl.  2
		$a_80_5 = {67 6f 6c 2e } //gol.  2
		$a_80_6 = {62 64 6c 65 76 65 6c 5c 65 67 61 72 6f 74 53 20 6c 61 63 6f 4c 5c 79 72 61 6e 61 63 64 72 6f 63 73 69 64 } //bdlevel\egarotS lacoL\yranacdrocsid  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*3+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=29
 
}
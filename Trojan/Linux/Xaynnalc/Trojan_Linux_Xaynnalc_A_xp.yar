
rule Trojan_Linux_Xaynnalc_A_xp{
	meta:
		description = "Trojan:Linux/Xaynnalc.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 62 61 73 68 5f 68 69 73 74 6f 72 79 } //1 /.bash_history
		$a_00_1 = {2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67 } //1 /dev/misc/watchdog
		$a_00_2 = {74 61 72 74 69 6e 67 20 64 64 6f 73 2e 2e 2e 00 00 } //1
		$a_00_3 = {00 10 64 00 00 e8 20 2e 00 10 e4 88 2d 40 ff fc 20 6e 00 0c 1d 50 ff f7 52 ae } //1
		$a_00_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}
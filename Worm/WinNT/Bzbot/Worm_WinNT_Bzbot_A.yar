
rule Worm_WinNT_Bzbot_A{
	meta:
		description = "Worm:WinNT/Bzbot.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 33 38 36 5c 62 6c 61 7a 65 62 6f 74 2e 70 64 62 } //1 i386\blazebot.pdb
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 70 00 69 00 67 00 73 00 75 00 78 00 } //1 \Device\pigsux
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
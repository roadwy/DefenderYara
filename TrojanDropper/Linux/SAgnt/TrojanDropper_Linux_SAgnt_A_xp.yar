
rule TrojanDropper_Linux_SAgnt_A_xp{
	meta:
		description = "TrojanDropper:Linux/SAgnt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 a0 10 40 00 48 c7 c1 b0 10 40 00 48 c7 c7 80 0a 40 00 } //3
		$a_00_1 = {b8 c8 16 60 00 55 48 2d c8 16 60 00 48 c1 f8 03 48 89 e5 48 89 c2 48 c1 ea 3f 48 01 d0 48 89 c6 48 d1 fe } //1
		$a_01_2 = {47 6f 6f 64 20 6c 75 63 6b 2c 20 45 62 6f 6c 61 2d 63 68 61 6e } //1 Good luck, Ebola-chan
		$a_01_3 = {25 73 20 25 73 20 2d 4f 2d 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c } //1 %s %s -O- 2>/dev/null
		$a_01_4 = {55 44 50 20 46 6c 6f 6f 64 65 72 } //1 UDP Flooder
		$a_01_5 = {53 74 61 72 74 69 6e 67 20 46 6c 6f 6f 64 } //1 Starting Flood
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
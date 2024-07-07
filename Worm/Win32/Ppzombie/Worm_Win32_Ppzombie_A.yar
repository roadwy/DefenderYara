
rule Worm_Win32_Ppzombie_A{
	meta:
		description = "Worm:Win32/Ppzombie.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 6c 6c 69 67 65 6e 74 20 50 32 50 20 5a 6f 6d 62 69 65 } //1 Intelligent P2P Zombie
		$a_01_1 = {00 25 73 5c 41 44 4d 49 4e 24 00 } //1
		$a_01_2 = {5b 2d 2d 69 6e 73 74 61 6c 6c 5d 20 5b 2d 2d 72 65 6d 6f 76 65 5d 20 5b 2d 2d 6c 6f 67 20 3c 6e 61 6d 65 3e 5d } //1 [--install] [--remove] [--log <name>]
		$a_01_3 = {00 25 73 5c 49 50 43 24 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
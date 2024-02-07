
rule Backdoor_Linux_DevilRobber_A{
	meta:
		description = "Backdoor:Linux/DevilRobber.A,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 07 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 63 72 65 65 6e 63 61 70 74 75 72 65 20 2d 54 20 30 20 2d 78 20 31 2e 70 6e 67 } //01 00  screencapture -T 0 -x 1.png
		$a_01_1 = {2f 6d 69 6e 65 72 2e 73 68 20 25 73 20 25 75 20 25 73 20 25 73 } //01 00  /miner.sh %s %u %s %s
		$a_01_2 = {2f 70 6f 6c 69 70 6f 20 2d 63 20 70 6f 6c 69 70 6f 2e 63 66 67 } //01 00  /polipo -c polipo.cfg
		$a_01_3 = {74 63 70 00 33 34 31 32 33 00 33 34 35 32 32 00 33 34 33 32 31 } //01 00 
		$a_01_4 = {25 23 2e 38 78 20 25 23 2e 38 78 20 25 23 2e 38 78 20 25 23 2e 38 78 20 25 23 2e 38 78 } //03 00  %#.8x %#.8x %#.8x %#.8x %#.8x
		$a_01_5 = {be 81 80 80 80 53 31 db 89 d9 0f af cb 83 c1 17 89 c8 f7 e6 c1 ea 07 89 d0 c1 e0 08 29 d0 29 c1 88 0c 1f 43 81 fb 00 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
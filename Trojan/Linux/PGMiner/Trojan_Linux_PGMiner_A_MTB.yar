
rule Trojan_Linux_PGMiner_A_MTB{
	meta:
		description = "Trojan:Linux/PGMiner.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0c 00 0c 00 07 00 00 05 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 58 31 31 2d 75 6e 69 78 2f 32 32 } //05 00  /tmp/.X11-unix/22
		$a_00_1 = {61 62 72 6f 78 75 28 63 6d 64 5f 6f 75 74 70 75 74 20 74 65 78 74 29 3b 43 4f 50 59 20 61 62 72 6f 78 75 20 46 52 4f 4d 20 50 52 4f 47 52 41 4d } //01 00  abroxu(cmd_output text);COPY abroxu FROM PROGRAM
		$a_00_2 = {31 37 32 2e 31 36 2e 30 2e 30 2f 31 32 } //01 00  172.16.0.0/12
		$a_00_3 = {31 39 32 2e 31 36 38 2e 30 2e 30 2f 31 36 } //01 00  192.168.0.0/16
		$a_00_4 = {31 30 2e 25 64 2e 30 2e 30 2f 31 36 } //01 00  10.%d.0.0/16
		$a_00_5 = {50 61 24 24 77 6f 72 64 31 32 33 34 35 36 } //01 00  Pa$$word123456
		$a_00_6 = {21 40 23 24 31 71 32 77 33 65 34 72 35 74 } //00 00  !@#$1q2w3e4r5t
	condition:
		any of ($a_*)
 
}

rule Worm_Linux_Moose_gen_A{
	meta:
		description = "Worm:Linux/Moose.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 2d 6e 20 2d 65 20 22 48 33 6c 4c 30 57 6f 52 6c 44 22 } //5 echo -n -e "H3lL0WoRlD"
		$a_01_1 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //5 stratum+tcp://
		$a_01_2 = {2f 43 68 61 6c 6c 65 6e 67 65 } //3 /Challenge
		$a_01_3 = {2f 68 6f 6d 65 2f 68 69 6b 2f 73 74 61 72 74 2e 73 68 } //5 /home/hik/start.sh
		$a_01_4 = {63 61 74 20 2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f } //3 cat /proc/cpuinfo
		$a_01_5 = {47 45 54 20 2f 78 78 2f 72 6e 64 65 2e 70 68 70 3f 70 3d 25 64 26 66 3d 25 64 26 6d 3d 25 64 20 48 54 54 50 2f 31 2e 31 } //4 GET /xx/rnde.php?p=%d&f=%d&m=%d HTTP/1.1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3+(#a_01_5  & 1)*4) >=18
 
}
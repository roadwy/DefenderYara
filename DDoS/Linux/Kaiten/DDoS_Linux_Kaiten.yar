
rule DDoS_Linux_Kaiten{
	meta:
		description = "DDoS:Linux/Kaiten,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 50 4f 4f 46 53 20 6d 65 20 6d 61 6e 75 61 6c 6c 79 2e } //4 SPOOFS me manually.
		$a_00_1 = {3e 62 6f 74 20 2b 73 74 64 20 3c 74 61 72 67 65 74 3e 20 3c 70 6f 72 74 3e 20 3c 73 65 63 73 3e } //2 >bot +std <target> <port> <secs>
		$a_00_2 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 2e 6c 6f 63 61 6c } //1 /etc/rc.d/rc.local
		$a_00_3 = {49 52 43 20 42 6f 74 00 } //1 剉⁃潂t
		$a_00_4 = {5b 55 4e 4b 5d 44 6f 6e 65 20 68 69 74 74 69 6e 67 } //2 [UNK]Done hitting
		$a_00_5 = {5b 55 4e 4b 5d 44 6f 6e 65 20 53 6c 61 6d 6d 69 6e 67 } //2 [UNK]Done Slamming
		$a_00_6 = {5b 4e 52 50 45 5d 20 41 74 74 61 63 6b 20 53 74 6f 70 70 65 64 } //2 [NRPE] Attack Stopped
		$a_00_7 = {62 65 65 6e 5f 74 68 65 72 65 5f 64 6f 6e 65 5f 74 68 61 74 } //2 been_there_done_that
		$a_00_8 = {6b 61 69 74 65 6e 2e 63 } //2 kaiten.c
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2) >=10
 
}
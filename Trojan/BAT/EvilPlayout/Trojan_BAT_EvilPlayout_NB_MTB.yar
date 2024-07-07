
rule Trojan_BAT_EvilPlayout_NB_MTB{
	meta:
		description = "Trojan:BAT/EvilPlayout.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {48 74 74 70 53 65 72 76 69 63 65 2e 70 64 62 } //3 HttpService.pdb
		$a_81_1 = {73 69 6d 70 6c 65 73 65 72 76 65 72 5c 48 74 74 70 53 65 72 76 69 63 65 } //3 simpleserver\HttpService
		$a_81_2 = {63 68 63 70 20 36 35 30 30 31 20 26 26 20 63 6d 64 20 2f 63 } //3 chcp 65001 && cmd /c
		$a_81_3 = {6c 6f 67 2e 74 78 74 } //3 log.txt
		$a_81_4 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 } //3 System.Net.Sockets
		$a_81_5 = {67 65 74 5f 49 6e 73 74 61 6c 6c 65 72 73 } //3 get_Installers
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
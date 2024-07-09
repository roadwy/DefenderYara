
rule TrojanDownloader_Linux_Korkerds_A_xp{
	meta:
		description = "TrojanDownloader:Linux/Korkerds.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 64 20 2d 69 20 27 24 64 27 20 2f 65 74 63 2f 63 72 6f 6e 74 61 62 } //1 sed -i '$d' /etc/crontab
		$a_01_1 = {63 68 6d 6f 64 20 2b 78 20 2f 62 69 6e 2f 68 74 74 70 64 6e 73 } //1 chmod +x /bin/httpdns
		$a_01_2 = {6e 6f 68 75 70 20 2f 62 69 6e 2f 73 68 20 2f 62 69 6e 2f 68 74 74 70 64 6e 73 } //1 nohup /bin/sh /bin/httpdns
		$a_03_3 = {2f 72 61 77 2f [0-10] 2d 6f 20 2f 62 69 6e 2f 68 74 74 70 64 6e 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
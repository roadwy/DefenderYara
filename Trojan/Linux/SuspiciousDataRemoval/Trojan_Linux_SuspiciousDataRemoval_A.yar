
rule Trojan_Linux_SuspiciousDataRemoval_A{
	meta:
		description = "Trojan:Linux/SuspiciousDataRemoval.A,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 5a 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 00 72 00 6d 00 } //40 /rm
		$a_00_1 = {20 00 2d 00 66 00 72 00 } //40  -fr
		$a_00_2 = {2f 00 76 00 61 00 72 00 2f 00 77 00 77 00 77 00 2f 00 } //10 /var/www/
		$a_00_3 = {2f 00 75 00 73 00 72 00 2f 00 73 00 68 00 61 00 72 00 65 00 2f 00 6e 00 67 00 69 00 6e 00 78 00 } //10 /usr/share/nginx
		$a_00_4 = {2f 00 76 00 61 00 72 00 2f 00 6c 00 69 00 62 00 2f 00 6d 00 79 00 73 00 71 00 6c 00 2f 00 } //10 /var/lib/mysql/
		$a_00_5 = {2f 00 76 00 61 00 72 00 2f 00 6c 00 69 00 62 00 2f 00 70 00 6f 00 73 00 74 00 67 00 72 00 65 00 73 00 71 00 6c 00 } //10 /var/lib/postgresql
	condition:
		((#a_00_0  & 1)*40+(#a_00_1  & 1)*40+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10) >=90
 
}
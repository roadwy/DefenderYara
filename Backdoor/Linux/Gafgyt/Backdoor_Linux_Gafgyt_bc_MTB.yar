
rule Backdoor_Linux_Gafgyt_bc_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.bc!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {76 73 65 61 74 74 61 63 6b } //1 vseattack
		$a_00_1 = {73 65 72 76 69 63 65 20 69 70 74 61 62 6c 65 73 20 73 74 6f 70 } //1 service iptables stop
		$a_00_2 = {30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 45 72 } //1 0n Ur FuCkInG FoReHeAd We BiG L33T HaxEr
		$a_00_3 = {73 65 72 76 69 63 65 20 66 69 72 65 77 61 6c 6c 64 20 73 74 6f 70 } //1 service firewalld stop
		$a_00_4 = {53 65 6e 64 48 54 54 50 48 65 78 } //1 SendHTTPHex
		$a_00_5 = {72 6d 20 2d 72 66 20 2f 74 6d 70 2f 2a 20 2f 76 61 72 2f 2a 20 2f 76 61 72 2f 72 75 6e 2f 2a 20 2f 76 61 72 2f 74 6d 70 2f 2a } //1 rm -rf /tmp/* /var/* /var/run/* /var/tmp/*
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
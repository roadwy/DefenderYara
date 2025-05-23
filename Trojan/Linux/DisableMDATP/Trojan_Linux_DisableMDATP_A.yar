
rule Trojan_Linux_DisableMDATP_A{
	meta:
		description = "Trojan:Linux/DisableMDATP.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 73 00 74 00 6f 00 70 00 20 00 6d 00 64 00 65 00 5f 00 6e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //10 systemctl stop mde_netfilter
		$a_00_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 6d 00 64 00 65 00 5f 00 6e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //10 systemctl disable mde_netfilter
		$a_00_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 73 00 74 00 6f 00 70 00 20 00 6d 00 64 00 65 00 5f 00 6e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 } //10 systemctl stop mde_netfilter.socket
		$a_00_3 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 6d 00 64 00 65 00 5f 00 6e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 } //10 systemctl disable mde_netfilter.socket
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=10
 
}
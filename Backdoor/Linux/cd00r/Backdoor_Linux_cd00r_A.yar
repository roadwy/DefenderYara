
rule Backdoor_Linux_cd00r_A{
	meta:
		description = "Backdoor:Linux/cd00r.A,SIGNATURE_TYPE_ELFHSTR_EXT,28 00 28 00 08 00 00 "
		
	strings :
		$a_80_0 = {63 64 72 5f 6f 70 65 6e 5f 64 6f 6f 72 } //cdr_open_door  5
		$a_80_1 = {63 64 72 5f 6e 6f 69 73 65 } //cdr_noise  5
		$a_80_2 = {70 63 61 70 2e 68 } //pcap.h  5
		$a_80_3 = {62 70 66 2e 68 } //bpf.h  5
		$a_80_4 = {53 65 6e 64 65 72 20 6d 69 73 6d 61 74 63 68 } //Sender mismatch  5
		$a_80_5 = {50 6f 72 74 20 25 64 20 69 73 20 67 6f 6f 64 20 61 73 20 63 6f 64 65 20 70 61 72 74 20 25 64 } //Port %d is good as code part %d  5
		$a_80_6 = {70 63 61 70 5f 6c 6f 6f 6b 75 70 6e 65 74 3a 20 25 73 } //pcap_lookupnet: %s  5
		$a_80_7 = {70 63 61 70 5f 6f 70 65 6e 5f 6c 69 76 65 3a 20 25 73 } //pcap_open_live: %s  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_80_6  & 1)*5+(#a_80_7  & 1)*5) >=40
 
}
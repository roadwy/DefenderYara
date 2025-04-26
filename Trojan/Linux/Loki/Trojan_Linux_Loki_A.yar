
rule Trojan_Linux_Loki_A{
	meta:
		description = "Trojan:Linux/Loki.A,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 73 74 61 74 } //2 /stat
		$a_00_1 = {2f 73 77 61 70 74 } //2 /swapt
		$a_00_2 = {2f 71 75 69 74 } //2 /quit
		$a_00_3 = {72 65 71 75 65 73 74 65 64 20 61 20 70 72 6f 74 6f 63 6f 6c 20 73 77 61 70 } //5 requested a protocol swap
		$a_00_4 = {72 65 71 75 65 73 74 65 64 20 61 6e 20 61 6c 6c 20 6b 69 6c 6c } //5 requested an all kill
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5) >=9
 
}

rule Trojan_Win32_Agent_SA{
	meta:
		description = "Trojan:Win32/Agent.SA,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 61 67 6f 67 65 2e 63 6f 6d } //sagoge.com  11
		$a_80_1 = {6d 61 63 75 77 75 66 2e 63 6f 6d } //macuwuf.com  11
		$a_80_2 = {62 75 6d 62 6c 65 62 65 65 } //bumblebee  1
		$a_80_3 = {70 73 68 65 6c 6c } //pshell  1
		$a_80_4 = {2f 67 65 74 5f 6c 6f 61 64 } ///get_load  1
		$a_80_5 = {68 61 6e 64 73 68 61 6b 65 } //handshake  1
	condition:
		((#a_80_0  & 1)*11+(#a_80_1  & 1)*11+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=15
 
}
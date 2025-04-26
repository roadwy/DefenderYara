
rule DoS_Linux_WprBlightre_A{
	meta:
		description = "DoS:Linux/WprBlightre.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 20 61 74 74 65 6d 70 74 20 77 68 69 6c 65 20 63 6c 6f 73 65 64 } //1 send attempt while closed
		$a_00_1 = {5b 21 5d 20 57 61 69 74 69 6e 67 20 46 6f 72 20 51 75 65 75 65 } //1 [!] Waiting For Queue
		$a_00_2 = {2e 00 00 00 42 00 00 00 69 00 00 00 42 00 00 00 69 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
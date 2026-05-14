
rule Trojan_Linux_Gafgyt_A_AMTB{
	meta:
		description = "Trojan:Linux/Gafgyt.A!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {31 35 38 2e 39 34 2e 32 31 30 2e 38 38 } //158.94.210.88  4
		$a_80_1 = {5b 25 73 3a 25 64 5d 20 64 65 74 65 63 74 65 64 20 6e 65 77 65 72 20 69 6e 73 74 61 6e 63 65 20 72 75 6e 6e 69 6e 67 21 20 73 75 69 63 69 64 65 28 29 } //[%s:%d] detected newer instance running! suicide()  3
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*3) >=7
 
}

rule DDoS_Linux_Mirai_YC_MTB{
	meta:
		description = "DDoS:Linux/Mirai.YC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {77 67 65 74 20 68 74 74 70 [0-02] 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f [0-60] 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 2e 2f } //1
		$a_00_1 = {5b 61 6e 74 69 68 6f 6e 65 79 5d 20 66 61 69 6c 65 64 20 73 74 61 67 65 20 31 20 68 6f 6e 65 79 70 6f 74 20 64 65 74 65 63 74 65 64 21 } //1 [antihoney] failed stage 1 honeypot detected!
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
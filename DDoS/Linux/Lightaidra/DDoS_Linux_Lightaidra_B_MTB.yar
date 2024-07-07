
rule DDoS_Linux_Lightaidra_B_MTB{
	meta:
		description = "DDoS:Linux/Lightaidra.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 79 74 65 73 74 2e 63 6f 2f 62 69 6e 73 2e 73 68 } //1 ://ytest.co/bins.sh
		$a_00_1 = {74 66 74 70 20 2d 67 20 79 74 65 73 74 2e 63 6f 20 2d 72 20 74 66 74 70 2e 73 68 } //1 tftp -g ytest.co -r tftp.sh
		$a_02_2 = {6e 61 6d 65 73 65 72 76 65 72 20 38 2e 38 2e 38 2e 38 90 01 02 6e 61 6d 65 73 65 72 76 65 72 20 38 2e 38 2e 34 2e 34 90 00 } //1
		$a_00_3 = {42 4f 54 20 4a 4f 49 4e 45 44 } //1 BOT JOINED
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
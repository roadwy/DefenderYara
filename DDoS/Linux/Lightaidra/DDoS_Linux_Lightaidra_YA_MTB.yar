
rule DDoS_Linux_Lightaidra_YA_MTB{
	meta:
		description = "DDoS:Linux/Lightaidra.YA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 74 70 67 65 74 20 2d 76 20 2d 75 20 61 6e 6f 6e 79 6d 6f 75 73 20 2d 70 20 61 6e 6f 6e 79 6d 6f 75 73 20 2d 50 20 32 31 } //1 ftpget -v -u anonymous -p anonymous -P 21
		$a_01_1 = {42 4f 41 54 20 43 52 41 43 4b 45 44 3a } //1 BOAT CRACKED:
		$a_01_2 = {53 65 72 76 65 72 5f 42 6f 74 70 6f 72 74 } //1 Server_Botport
		$a_01_3 = {48 61 63 6b 65 72 53 63 61 6e 32 } //1 HackerScan2
		$a_01_4 = {62 6f 74 6b 69 6c 6c 65 72 } //1 botkiller
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}

rule Trojan_MacOS_Rustbucket_AR{
	meta:
		description = "Trojan:MacOS/Rustbucket.AR,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_02_0 = {75 6e 7a 69 70 20 [0-08] 2f 55 73 65 72 73 2f 53 68 61 72 65 64 } //4
		$a_02_1 = {63 68 6d 6f 64 20 2b 78 [0-08] 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f } //1
		$a_02_2 = {63 68 6d 6f 64 20 37 [0-08] 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f } //1
		$a_02_3 = {6f 70 65 6e 20 [0-08] 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f } //2
	condition:
		((#a_02_0  & 1)*4+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*2) >=7
 
}
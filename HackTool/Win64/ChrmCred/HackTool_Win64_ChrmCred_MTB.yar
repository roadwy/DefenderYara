
rule HackTool_Win64_ChrmCred_MTB{
	meta:
		description = "HackTool:Win64/ChrmCred!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 6f 6d 65 70 61 73 73 20 43 72 65 64 65 6e 74 69 61 6c 73 } //1 Chromepass Credentials
		$a_01_1 = {73 6d 74 70 2e 67 6d 61 69 6c 2e 63 6f 6d } //1 smtp.gmail.com
		$a_01_2 = {63 61 6e 6e 6f 74 20 72 65 61 64 20 61 20 74 65 78 74 20 63 6f 6c 75 6d 6e } //1 cannot read a text column
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //1 https://api.ipify.org
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
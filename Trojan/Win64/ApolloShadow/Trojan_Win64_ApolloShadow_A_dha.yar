
rule Trojan_Win64_ApolloShadow_A_dha{
	meta:
		description = "Trojan:Win64/ApolloShadow.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 00 69 00 6d 00 65 00 73 00 74 00 61 00 6d 00 70 00 2e 00 64 00 69 00 67 00 69 00 63 00 65 00 72 00 74 00 2e 00 63 00 6f 00 6d 00 } //1 timestamp.digicert.com
		$a_01_1 = {2f 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 } //1 /registered
		$a_01_2 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 66 00 20 00 2d 00 45 00 6e 00 74 00 65 00 72 00 70 00 72 00 69 00 73 00 65 00 20 00 2d 00 61 00 64 00 64 00 73 00 74 00 6f 00 72 00 65 00 } //1 certutil.exe -f -Enterprise -addstore
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
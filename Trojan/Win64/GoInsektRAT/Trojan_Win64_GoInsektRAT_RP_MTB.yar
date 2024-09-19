
rule Trojan_Win64_GoInsektRAT_RP_MTB{
	meta:
		description = "Trojan:Win64/GoInsektRAT.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6d 33 2f 63 6f 6e 6e 65 63 74 2f 70 72 6f 74 6c 73 2e 53 65 74 50 61 73 77 64 } //1 pm3/connect/protls.SetPaswd
		$a_01_1 = {70 6d 33 2f 70 6c 75 67 69 6e 73 2f 63 6f 64 65 2e 53 68 65 6c 6c 43 6f 64 65 } //1 pm3/plugins/code.ShellCode
		$a_01_2 = {70 6d 33 2f 63 6f 6e 6e 65 63 74 2f 70 72 6f 73 6e 69 2f 63 6c 69 65 6e 74 2e 67 6f } //1 pm3/connect/prosni/client.go
		$a_01_3 = {70 6d 33 2f 63 6f 6e 6e 65 63 74 2f 70 72 6f 73 6e 69 2f 73 65 72 76 65 72 2e 67 6f } //1 pm3/connect/prosni/server.go
		$a_01_4 = {70 6d 33 2f 61 70 70 73 2f 49 6e 73 65 6b 74 2f 6d 61 69 6e 2e 67 6f } //10 pm3/apps/Insekt/main.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=14
 
}
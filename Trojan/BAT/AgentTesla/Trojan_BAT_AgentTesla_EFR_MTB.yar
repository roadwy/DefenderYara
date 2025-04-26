
rule Trojan_BAT_AgentTesla_EFR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 00 42 00 43 00 42 00 43 00 58 00 4e 00 42 00 4e 00 43 00 42 00 4e 00 43 00 42 00 4d 00 42 00 4e 00 43 00 58 00 4e 00 43 00 58 00 4e 00 43 00 4e 00 58 00 42 00 43 00 4e 00 42 00 58 00 } //1 NBCBCXNBNCBNCBMBNCXNCXNCNXBCNBX
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {41 00 73 00 70 00 6e 00 65 00 74 00 5f 00 63 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 Aspnet_compiler.exe
		$a_01_3 = {00 47 65 74 54 79 70 65 } //1 䜀瑥祔数
		$a_01_4 = {74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 } //1 transfer.sh
		$a_01_5 = {53 00 6b 00 69 00 64 00 6f 00 6d 00 6f 00 6e 00 65 00 79 00 2e 00 4d 00 6f 00 6e 00 65 00 79 00 } //1 Skidomoney.Money
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule Trojan_Win64_ClipBanker_EB_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 64 32 57 69 74 68 52 53 41 45 6e 63 72 79 70 74 69 6f 6e } //1 md2WithRSAEncryption
		$a_01_1 = {57 73 50 2f 56 79 63 64 35 65 69 48 67 43 30 57 68 70 59 4d 77 73 6b 41 6a 57 46 36 68 61 35 63 51 31 7a 77 4e 45 68 65 55 79 30 3d } //1 WsP/Vycd5eiHgC0WhpYMwskAjWF6ha5cQ1zwNEheUy0=
		$a_01_2 = {50 6c 65 61 73 65 20 53 65 6c 65 63 74 20 42 6f 74 } //1 Please Select Bot
		$a_01_3 = {53 69 2d 70 61 6c 69 6e 67 2d 75 6d 62 65 72 65 6c 61 5c 47 72 6f 77 74 6f 70 69 61 20 4d 75 6c 74 69 42 6f 74 } //1 Si-paling-umberela\Growtopia MultiBot
		$a_01_4 = {70 72 6f 6a 65 63 74 2d 75 6d 62 72 65 6c 6c 61 2e 70 64 62 } //1 project-umbrella.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}

rule Trojan_Win32_LummaStealer_EC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 6f 70 57 47 69 70 70 54 66 67 2e 64 65 66 65 72 77 72 61 70 32 } //1 main.opWGippTfg.deferwrap2
		$a_81_1 = {6d 61 69 6e 2e 6f 70 57 47 69 70 70 54 66 67 2e 64 65 66 65 72 77 72 61 70 31 } //1 main.opWGippTfg.deferwrap1
		$a_81_2 = {6d 61 69 6e 2e 4b 71 71 41 56 6d 6a 61 6e 4a } //1 main.KqqAVmjanJ
		$a_81_3 = {6d 61 69 6e 2e 66 51 79 66 54 47 50 55 74 71 } //1 main.fQyfTGPUtq
		$a_81_4 = {65 78 69 74 68 6f 6f 6b 2f 68 6f 6f 6b 73 2e 67 6f } //1 exithook/hooks.go
		$a_81_5 = {67 6f 2d 74 65 6c 65 67 72 61 6d 2d 62 6f 74 2d 61 70 69 } //1 go-telegram-bot-api
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
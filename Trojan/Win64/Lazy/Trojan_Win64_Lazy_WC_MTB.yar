
rule Trojan_Win64_Lazy_WC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.WC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_1 = {6e 61 76 65 67 61 64 6f 72 2f 6c 6f 67 67 65 72 2e 43 6f 6e 66 69 67 75 72 65 } //1 navegador/logger.Configure
		$a_81_2 = {6d 61 69 6e 2e 45 78 65 63 75 74 65 } //1 main.Execute
		$a_81_3 = {6e 61 76 65 67 61 64 6f 72 2f 63 6d 64 2f 6e 61 76 65 67 61 64 6f 72 } //1 navegador/cmd/navegador
		$a_81_4 = {6e 61 76 65 67 61 64 6f 72 2f 6c 6f 67 67 65 72 2e 28 2a 4c 6f 67 67 65 72 29 2e 53 65 74 56 65 72 62 6f 73 65 } //1 navegador/logger.(*Logger).SetVerbose
		$a_81_5 = {59 73 49 6d 66 53 42 6f 50 39 51 50 59 4c 30 78 79 4b 4a 50 71 30 67 63 61 4a 64 47 33 72 49 6e 6f 71 78 54 57 62 66 51 75 39 4d 3d } //1 YsImfSBoP9QPYL0xyKJPq0gcaJdG3rInoqxTWbfQu9M=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
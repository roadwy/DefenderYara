
rule Trojan_Win64_DllHijack_LMA_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 d2 49 8b c0 49 f7 f2 0f b6 04 0a 43 30 04 01 49 ff c0 48 8b 4c 24 48 48 8b c1 4c 8b 4c 24 40 49 2b c1 4c 3b c0 } //20
		$a_81_1 = {45 72 72 6f 20 61 6f 20 63 61 72 72 65 67 61 72 20 6f 20 61 72 71 75 69 76 6f 20 44 4c 4c 20 70 61 72 61 20 6d 65 6d } //10 Erro ao carregar o arquivo DLL para mem
		$a_81_2 = {64 75 6c 6f 20 65 6d 20 6d 65 6d } //3 dulo em mem
		$a_81_3 = {45 72 72 6f 20 61 6f 20 63 61 72 72 65 67 61 72 20 61 20 44 4c 4c 20 6e 61 20 6d 65 6d } //2 Erro ao carregar a DLL na mem
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*3+(#a_81_3  & 1)*2) >=35
 
}
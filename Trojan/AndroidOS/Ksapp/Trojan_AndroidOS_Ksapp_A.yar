
rule Trojan_AndroidOS_Ksapp_A{
	meta:
		description = "Trojan:AndroidOS/Ksapp.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 73 64 2f 74 65 43 65 72 2f 71 64 74 68 65 79 74 2f 71 2f 72 3b } //1 Lsd/teCer/qdtheyt/q/r;
		$a_01_1 = {4c 73 65 43 2f 76 42 4f 76 79 69 78 2f 69 6b 66 75 68 43 71 68 79 65 61 72 6d 61 2f 57 71 43 75 51 66 66 42 79 73 71 6a 79 65 64 3b } //1 LseC/vBOvyix/ikfuhCqhyearma/WqCuQffBysqjyed;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
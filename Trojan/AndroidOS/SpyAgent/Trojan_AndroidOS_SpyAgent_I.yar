
rule Trojan_AndroidOS_SpyAgent_I{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.I,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 41 70 70 44 61 74 61 55 73 65 72 } //2 bAppDataUser
		$a_01_1 = {41 70 69 43 6f 6e 74 72 6f 6c 6c 65 72 2f 61 64 64 73 } //2 ApiController/adds
		$a_01_2 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 2f 49 52 65 71 75 65 73 74 53 65 72 76 69 63 65 3b } //2 Lcom/example/test/IRequestService;
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
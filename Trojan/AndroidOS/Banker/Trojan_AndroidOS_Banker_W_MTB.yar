
rule Trojan_AndroidOS_Banker_W_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 61 6e 65 77 } //1 com/example/anew
		$a_01_1 = {45 58 54 52 41 5f 53 4b 49 50 5f 46 49 4c 45 5f 4f 50 45 52 41 54 49 4f 4e } //1 EXTRA_SKIP_FILE_OPERATION
		$a_01_2 = {52 45 53 55 4c 54 5f 49 4e 53 54 41 4c 4c 5f 53 55 43 43 45 53 53 } //1 RESULT_INSTALL_SUCCESS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win32_CryptInject_BKL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4d 79 43 61 6c 6c 55 70 64 61 74 65 } //1 MyCallUpdate
		$a_81_1 = {45 72 72 6f 20 61 6f 20 6c 6f 63 61 6c 69 7a 61 72 20 61 20 66 75 6e } //1 Erro ao localizar a fun
		$a_81_2 = {43 6c 61 73 73 69 63 49 45 44 4c 4c 5f 36 34 2e 64 6c 6c } //1 ClassicIEDLL_64.dll
		$a_81_3 = {53 61 61 53 41 50 49 2e 6a 73 6f 6e } //1 SaaSAPI.json
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
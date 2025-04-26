
rule Trojan_AndroidOS_BankerAgent_T{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 63 74 69 76 65 49 6e 6a 65 63 74 41 70 70 50 61 63 6b 61 67 65 } //2 activeInjectAppPackage
		$a_01_1 = {69 73 48 69 64 64 65 6e 56 4e 43 } //2 isHiddenVNC
		$a_01_2 = {61 63 74 69 76 65 49 6e 6a 65 63 74 4c 6f 67 49 64 } //2 activeInjectLogId
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}

rule Trojan_AndroidOS_Grifthorse_T{
	meta:
		description = "Trojan:AndroidOS/Grifthorse.T,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 4c 45 41 52 5f 48 49 53 54 4f 52 59 5f 54 52 49 47 47 45 52 53 5f 4f 4e 43 45 } //1 CLEAR_HISTORY_TRIGGERS_ONCE
		$a_01_1 = {54 65 73 74 49 6e 73 74 61 6c 6c 49 6e 66 6f } //1 TestInstallInfo
		$a_01_2 = {43 43 61 6c 6c 62 61 63 6b } //1 CCallback
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
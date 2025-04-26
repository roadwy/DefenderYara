
rule Trojan_AndroidOS_Opfake_TE{
	meta:
		description = "Trojan:AndroidOS/Opfake.TE,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 52 56 64 52 56 38 42 2e 51 59 45 51 2e 56 2e 45 52 73 20 35 45 3f 4f 38 63 6d 56 6d 6a 20 52 6d 4f 64 4a } //1 ERVdRV8B.QYEQ.V.ERs 5E?O8cmVmj RmOdJ
		$a_01_1 = {63 6f 59 75 2e 43 6d 56 64 } //1 coYu.CmVd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}

rule Trojan_BAT_Quasar_MBGX_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MBGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 68 66 66 73 6b 64 67 73 66 6b 64 66 66 66 64 64 66 72 66 66 66 66 64 68 66 66 73 63 66 64 66 } //1 nhffskdgsfkdfffddfrffffdhffscfdf
		$a_01_1 = {63 68 66 64 66 67 66 64 6b 66 66 73 66 68 64 64 68 64 73 68 64 67 68 66 } //1 chfdfgfdkffsfhddhdshdghf
		$a_01_2 = {68 6b 67 66 66 66 67 73 64 66 66 64 68 64 72 66 64 66 64 66 64 73 73 68 63 66 } //1 hkgfffgsdffdhdrfdfdfdsshcf
		$a_01_3 = {6a 6b 41 61 61 6b 6b 69 6a 66 65 72 6a 46 49 46 70 70 70 62 6d 6d 63 53 69 64 62 69 6c 53 6b 66 49 61 6c 63 61 62 6e 70 6f 6a 64 69 6b 6e 6e 46 67 46 69 6c 6b 62 6b 46 69 53 70 66 70 63 46 6b 64 53 41 69 6b 70 6d 6e 62 53 6b 64 69 72 68 49 66 65 62 6e 6f 53 6d 72 6f 6f 49 62 6b } //1 jkAaakkijferjFIFpppbmmcSidbilSkfIalcabnpojdiknnFgFilkbkFiSpfpcFkdSAikpmnbSkdirhIfebnoSmrooIbk
		$a_01_4 = {67 67 6a 66 67 73 73 66 64 66 68 } //1 ggjfgssfdfh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
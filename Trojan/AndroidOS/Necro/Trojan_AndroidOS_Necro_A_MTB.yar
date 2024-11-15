
rule Trojan_AndroidOS_Necro_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Necro.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 73 65 53 74 61 72 74 4e 6f 74 69 66 79 } //1 useStartNotify
		$a_01_1 = {75 73 65 46 75 6c 6c 49 6e 6a 65 63 74 } //1 useFullInject
		$a_01_2 = {4c 73 64 6b 2f 6e 69 63 72 6f 2f 77 65 62 } //1 Lsdk/nicro/web
		$a_01_3 = {77 65 62 61 64 6c 69 73 74 } //1 webadlist
		$a_01_4 = {65 78 65 63 75 74 65 64 53 65 61 72 63 68 55 72 6c 73 } //1 executedSearchUrls
		$a_01_5 = {44 65 62 75 67 2e 77 65 62 45 78 65 63 } //1 Debug.webExec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
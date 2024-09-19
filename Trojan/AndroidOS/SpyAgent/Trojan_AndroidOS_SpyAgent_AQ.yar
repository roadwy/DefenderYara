
rule Trojan_AndroidOS_SpyAgent_AQ{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AQ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 68 61 68 61 2f 68 6f 6d 6f 67 65 50 6e 65 6f 75 73 } //2 wwwhaha/homogePneous
		$a_01_1 = {6d 79 6d 66 2f 46 75 6c 6c 73 63 72 65 65 6e 41 63 74 69 76 69 74 79 } //2 mymf/FullscreenActivity
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
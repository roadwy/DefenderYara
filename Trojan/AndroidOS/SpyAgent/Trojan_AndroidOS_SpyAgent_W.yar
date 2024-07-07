
rule Trojan_AndroidOS_SpyAgent_W{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.W,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 56 69 64 65 6f 20 5c 64 } //1 startVideo \d
		$a_01_1 = {2d 2d 20 20 46 72 6f 6e 74 20 43 61 6d 65 72 61 } //1 --  Front Camera
		$a_01_2 = {74 61 6b 65 70 69 63 20 5c 64 } //1 takepic \d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_AndroidOS_SpyAgent_W_2{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.W,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 75 73 63 72 65 61 74 65 73 } //2 onuscreates
		$a_01_1 = {70 68 69 73 64 61 74 61 73 65 74 75 70 } //2 phisdatasetup
		$a_01_2 = {2f 61 70 6b 66 72 6f 6d 68 65 6c 6c 74 6f 79 6f 75 66 6f 72 74 68 69 73 } //2 /apkfromhelltoyouforthis
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
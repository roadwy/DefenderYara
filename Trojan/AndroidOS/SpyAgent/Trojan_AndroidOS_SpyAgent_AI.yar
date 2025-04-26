
rule Trojan_AndroidOS_SpyAgent_AI{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AI,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 47 65 74 50 69 63 55 73 65 } //2 ScreenGetPicUse
		$a_01_1 = {41 6c 6c 6f 77 50 72 69 6d 73 31 34 2d 73 74 61 72 74 58 3a } //2 AllowPrims14-startX:
		$a_01_2 = {53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 45 6e 63 6f 64 65 55 73 65 } //2 ScreenRecorderEncodeUse
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
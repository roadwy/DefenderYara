
rule HackTool_AndroidOS_DDos_B_MTB{
	meta:
		description = "HackTool:AndroidOS/DDos.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 64 72 6f 69 64 70 72 6f 6a 65 63 74 2f 64 64 6f 73 } //2 com/droidproject/ddos
		$a_01_1 = {44 4f 53 4c 6f 63 6b } //1 DOSLock
		$a_01_2 = {6c 6f 63 6b 43 6c 69 63 6b 65 64 } //1 lockClicked
		$a_01_3 = {64 6f 73 53 65 72 76 69 63 65 } //1 dosService
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
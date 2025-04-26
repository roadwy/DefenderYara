
rule HackTool_AndroidOS_Doods_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Doods.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 65 6e 69 75 73 2f 6d 6f 68 61 6d 6d 61 64 2f 6c 6f 69 63 } //1 genius/mohammad/loic
		$a_00_1 = {2f 6c 6f 69 63 2f 53 65 72 76 69 63 65 44 65 6e 69 65 72 } //1 /loic/ServiceDenier
		$a_00_2 = {44 44 4f 53 } //1 DDOS
		$a_01_3 = {73 65 6c 65 63 74 65 64 54 61 72 67 65 74 54 56 } //1 selectedTargetTV
		$a_01_4 = {73 70 65 65 64 54 72 61 63 6b 62 61 72 } //1 speedTrackbar
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
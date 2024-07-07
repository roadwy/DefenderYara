
rule TrojanDropper_WinNT_Malscript_A_MTB{
	meta:
		description = "TrojanDropper:WinNT/Malscript.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 6f 69 61 75 63 7a 6d 65 61 2f 4d 62 73 69 62 6c 79 6c 73 6d 6d } //1 woiauczmea/Mbsiblylsmm
		$a_00_1 = {66 75 74 69 71 76 71 68 68 79 2e 6a 73 } //1 futiqvqhhy.js
		$a_00_2 = {72 65 73 6f 75 72 63 65 73 2f 73 64 62 6a 7a 6a 6d 69 75 76 } //1 resources/sdbjzjmiuv
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
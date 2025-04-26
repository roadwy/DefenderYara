
rule TrojanDropper_AndroidOS_SAgnt_F_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 00 22 01 ?? ?? 71 10 ?? ?? 08 00 0c 02 70 20 ?? ?? 21 00 22 02 ?? ?? 70 10 ?? ?? 02 00 6e 10 ?? ?? 09 00 0c 03 6e 10 ?? ?? 01 00 0c 04 21 45 01 01 35 50 13 00 49 06 04 00 21 37 94 07 01 07 49 07 03 07 b7 76 8e 66 6e 20 ?? ?? 62 00 d8 01 01 01 d8 00 00 01 28 ee 6e 10 ?? ?? 02 00 0c 00 11 00 } //2
		$a_00_1 = {63 6f 6d 2e 6a 73 68 61 72 65 35 2e } //1 com.jshare5.
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}
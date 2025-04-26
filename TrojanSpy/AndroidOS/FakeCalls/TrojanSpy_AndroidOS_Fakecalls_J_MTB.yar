
rule TrojanSpy_AndroidOS_Fakecalls_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecalls.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 77 69 73 68 2f 64 65 66 61 75 6c 74 63 61 6c 6c 73 65 72 76 69 63 65 2f 61 63 74 69 76 69 74 79 2f 56 61 6c 69 64 41 63 74 69 76 69 74 79 53 4b 56 } //1 com/wish/defaultcallservice/activity/ValidActivitySKV
		$a_03_1 = {01 01 02 14 02 ?? 00 08 7f 6e 20 d5 00 21 00 0c 02 6e 20 ?? ?? 12 00 14 02 ?? 01 08 7f 6e 20 d5 00 21 00 0c 02 6e 20 ?? ?? 12 00 14 02 ?? 00 08 7f 6e 20 d5 00 21 00 0c 02 6e 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
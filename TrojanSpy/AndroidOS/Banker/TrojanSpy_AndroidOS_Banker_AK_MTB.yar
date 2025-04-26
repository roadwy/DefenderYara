
rule TrojanSpy_AndroidOS_Banker_AK_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 72 35 21 30 00 52 62 ?? ?? d8 02 02 01 d4 22 00 01 59 62 ?? ?? 52 63 ?? ?? 54 64 ?? ?? 44 05 04 02 b0 53 d4 33 00 01 59 63 ?? ?? 70 40 ?? ?? 26 43 54 62 ?? ?? 52 63 ?? ?? 44 03 02 03 52 64 ?? ?? 44 04 02 04 b0 43 d4 33 00 01 44 02 02 03 48 03 07 01 b7 32 8d 22 4f 02 00 01 d8 01 01 01 } //1
		$a_01_1 = {6e 6f 74 69 66 5f 6f 70 65 6e } //1 notif_open
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
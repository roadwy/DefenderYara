
rule TrojanSpy_AndroidOS_Banker_B{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {4a 61 76 6d 61 76 53 65 72 76 69 63 65 } //2 JavmavService
		$a_00_1 = {56 6f 61 63 41 63 74 69 76 69 74 79 } //2 VoacActivity
		$a_00_2 = {2f 4d 61 73 52 65 63 65 69 76 65 72 3b } //1 /MasReceiver;
		$a_00_3 = {2f 64 77 65 73 52 65 63 65 69 76 65 72 3b } //1 /dwesReceiver;
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
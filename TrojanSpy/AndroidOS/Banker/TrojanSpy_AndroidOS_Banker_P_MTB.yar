
rule TrojanSpy_AndroidOS_Banker_P_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6d 69 6c 6c 65 2f 6d 67 78 2f 67 65 74 64 65 66 61 75 6c 74 73 6d 73 5f 61 63 74 69 76 69 74 79 } //1 com/mille/mgx/getdefaultsms_activity
		$a_00_1 = {61 63 74 69 76 69 74 79 5f 6b 65 79 70 72 65 73 73 } //1 activity_keypress
		$a_00_2 = {70 75 78 61 53 4d 53 4c 6f 6f 70 } //1 puxaSMSLoop
		$a_00_3 = {73 6d 73 70 75 73 68 5f 42 52 } //1 smspush_BR
		$a_00_4 = {62 69 74 2e 64 6f 2f 61 63 74 69 76 61 63 69 6f 6e 6e } //1 bit.do/activacionn
		$a_00_5 = {6d 65 5f 64 65 76 69 63 65 2e 69 6e 69 } //1 me_device.ini
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
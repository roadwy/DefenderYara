
rule TrojanSpy_AndroidOS_Zanubis_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Zanubis.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 74 61 72 67 65 74 72 65 6d 6f 76 65 } //1 notargetremove
		$a_01_1 = {64 65 73 42 6c 6f 71 75 65 6f 55 70 64 61 74 65 } //1 desBloqueoUpdate
		$a_01_2 = {62 6c 6f 71 75 65 6f 41 6c 6c 55 70 64 61 74 65 } //1 bloqueoAllUpdate
		$a_01_3 = {73 65 74 74 69 6e 67 73 2e 76 65 72 69 66 79 61 70 70 73 73 65 74 74 69 6e 67 73 61 63 74 69 76 69 74 79 } //1 settings.verifyappssettingsactivity
		$a_01_4 = {61 6c 65 72 74 61 72 42 6c 6f 71 75 65 6f } //1 alertarBloqueo
		$a_01_5 = {70 6f 69 69 74 79 67 75 6e 73 77 65 77 6e 69 6f 66 6e 74 77 65 69 6f 75 73 64 6e 68 6b 77 71 } //1 poiitygunswewniofntweiousdnhkwq
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
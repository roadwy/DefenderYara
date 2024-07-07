
rule Trojan_AndroidOS_Origami_Y{
	meta:
		description = "Trojan:AndroidOS/Origami.Y,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 65 73 74 69 6e 67 36 37 } //1 testing67
		$a_01_1 = {49 74 73 20 61 20 53 79 73 74 65 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e } //1 Its a System Application
		$a_01_2 = {46 6f 72 20 66 69 20 2b 20 66 69 } //1 For fi + fi
		$a_01_3 = {2e 2e 59 4f 55 52 20 54 45 58 54 20 48 45 52 45 2e 2e 2e } //1 ..YOUR TEXT HERE...
		$a_01_4 = {69 6e 20 74 69 6d 65 72 20 2b 2b 2b 2b } //1 in timer ++++
		$a_01_5 = {4c 69 6d 65 2f 73 65 72 76 69 63 65 69 6e 66 6f 2f 61 70 70 2f 71 73 74 75 6e 74 68 6f 6e 67 2f 71 53 65 6e 73 6f 72 53 65 72 76 69 63 65 68 6f 6e 67 } //1 Lime/serviceinfo/app/qstunthong/qSensorServicehong
		$a_01_6 = {43 61 6e 27 74 20 54 75 72 6e 20 4f 46 46 20 41 63 74 69 76 61 74 69 6f 6e } //1 Can't Turn OFF Activation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
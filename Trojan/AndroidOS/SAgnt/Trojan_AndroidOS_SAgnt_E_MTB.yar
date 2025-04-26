
rule Trojan_AndroidOS_SAgnt_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 64 64 2f 61 6e 64 72 6f 69 64 2f 69 6e 74 65 72 63 65 70 74 6d 6d 73 } //1 fdd/android/interceptmms
		$a_00_1 = {67 65 74 63 6f 6e 74 65 6e 74 72 65 73 6f 6c 76 65 72 } //1 getcontentresolver
		$a_00_2 = {73 6d 73 5f 72 65 63 65 69 76 65 64 } //1 sms_received
		$a_00_3 = {2f 63 6f 6e 74 65 6e 74 2f 63 6f 6d 70 6f 6e 65 6e 74 6e 61 6d 65 } //1 /content/componentname
		$a_00_4 = {6f 6e 73 74 61 72 74 63 6f 6d 6d 61 6e 64 } //1 onstartcommand
		$a_01_5 = {52 65 74 72 69 65 76 65 43 6f 6e 66 3a 50 68 6f 6e 65 } //1 RetrieveConf:Phone
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule Trojan_BAT_Keylogger_ABAS_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.ABAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 28 01 00 00 06 0d 09 20 01 80 00 00 40 aa 02 00 00 72 56 01 00 70 13 04 7e 01 00 00 04 17 58 80 01 00 00 04 08 28 15 00 00 0a 28 09 00 00 06 13 04 72 58 01 00 70 17 } //1
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 } //1 keylogger
		$a_01_2 = {75 00 61 00 63 00 5f 00 74 00 72 00 75 00 65 00 } //1 uac_true
		$a_01_3 = {70 00 65 00 72 00 73 00 69 00 73 00 74 00 65 00 6e 00 63 00 65 00 5f 00 74 00 72 00 75 00 65 00 } //1 persistence_true
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
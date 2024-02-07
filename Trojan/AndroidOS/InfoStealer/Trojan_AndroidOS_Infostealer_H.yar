
rule Trojan_AndroidOS_Infostealer_H{
	meta:
		description = "Trojan:AndroidOS/Infostealer.H,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 6c 72 6f 6d 65 6e 74 2e 74 6b 2f 74 } //02 00  alroment.tk/t
		$a_01_1 = {52 65 73 75 6d 61 62 6c 65 53 75 62 5f 66 6d 5f 4d 65 73 73 61 67 65 41 72 72 69 76 65 64 } //02 00  ResumableSub_fm_MessageArrived
		$a_01_2 = {70 6e 73 65 72 76 69 63 65 5f 42 52 } //02 00  pnservice_BR
		$a_01_3 = {5f 61 70 69 6c 69 6e 6b } //00 00  _apilink
	condition:
		any of ($a_*)
 
}
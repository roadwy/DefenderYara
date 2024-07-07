
rule Trojan_AndroidOS_Infostealer_G{
	meta:
		description = "Trojan:AndroidOS/Infostealer.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 66 68 69 61 68 77 66 69 68 77 61 6c 2e 74 6b 2f 68 61 6a 6d 61 6e } //2 wfhiahwfihwal.tk/hajman
		$a_01_1 = {52 65 73 75 6d 61 62 6c 65 53 75 62 5f 66 6d 5f 4d 65 73 73 61 67 65 41 72 72 69 76 65 64 } //2 ResumableSub_fm_MessageArrived
		$a_01_2 = {5f 73 65 6e 64 6c 61 72 67 65 73 6d 73 } //2 _sendlargesms
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
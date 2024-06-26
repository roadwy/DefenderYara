
rule Trojan_AndroidOS_Tiny_A{
	meta:
		description = "Trojan:AndroidOS/Tiny.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 09 00 00 03 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 66 69 78 75 70 2f 75 73 62 68 75 62 } //03 00  Lcom/fixup/usbhub
		$a_01_1 = {4c 63 6f 6d 2f 73 74 61 72 74 2f 63 61 72 72 69 65 72 } //03 00  Lcom/start/carrier
		$a_01_2 = {4c 63 6f 6d 2f 69 70 65 72 66 2f 61 75 64 69 6f 64 } //01 00  Lcom/iperf/audiod
		$a_01_3 = {52 65 63 65 69 76 65 72 6f 68 74 71 } //01 00  Receiverohtq
		$a_01_4 = {53 65 72 76 69 63 65 6f 68 74 71 } //01 00  Serviceohtq
		$a_01_5 = {52 65 63 65 69 76 65 72 77 6b 64 71 } //01 00  Receiverwkdq
		$a_01_6 = {53 65 72 76 69 63 65 77 6b 64 71 } //01 00  Servicewkdq
		$a_01_7 = {52 65 63 65 69 76 65 72 66 62 69 75 } //01 00  Receiverfbiu
		$a_01_8 = {53 65 72 76 69 63 65 66 62 69 75 } //00 00  Servicefbiu
	condition:
		any of ($a_*)
 
}

rule Trojan_AndroidOS_Boogr_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Boogr.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 72 6c 2e 74 78 74 } //01 00  url.txt
		$a_00_1 = {43 61 6e 6e 6f 74 20 73 65 6e 64 20 66 69 6c 65 73 20 66 72 6f 6d 20 74 68 65 20 61 73 73 65 74 73 20 66 6f 6c 64 65 72 } //01 00  Cannot send files from the assets folder
		$a_00_2 = {4c 63 6f 6d 2f 72 65 7a 61 2f 73 68 2f 64 65 76 69 63 65 69 6e 66 6f 2f 44 69 76 69 63 65 49 6e 66 6f } //01 00  Lcom/reza/sh/deviceinfo/DiviceInfo
		$a_00_3 = {68 69 64 65 69 63 6f 6e } //01 00  hideicon
		$a_00_4 = {67 65 74 64 65 76 69 63 65 66 75 6c 6c 69 6e 66 6f } //01 00  getdevicefullinfo
		$a_00_5 = {53 65 6e 64 53 69 6e 67 6c 65 4d 65 73 73 61 67 65 } //01 00  SendSingleMessage
		$a_00_6 = {6f 6e 73 74 61 72 74 63 6f 6d 6d 61 6e 64 } //01 00  onstartcommand
		$a_00_7 = {72 61 74 2e 70 68 70 } //00 00  rat.php
	condition:
		any of ($a_*)
 
}
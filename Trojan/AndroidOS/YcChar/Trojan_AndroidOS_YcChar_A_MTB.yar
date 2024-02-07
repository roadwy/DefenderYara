
rule Trojan_AndroidOS_YcChar_A_MTB{
	meta:
		description = "Trojan:AndroidOS/YcChar.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {79 63 63 68 61 72 67 65 } //01 00  yccharge
		$a_00_1 = {2f 79 2f 67 61 6d 65 2e 6a 73 70 3f 63 68 61 72 67 65 70 61 72 61 3d } //01 00  /y/game.jsp?chargepara=
		$a_00_2 = {2f 69 74 65 6d 2f 66 61 63 65 2e 70 68 70 } //01 00  /item/face.php
		$a_00_3 = {2f 70 6f 6b 65 72 2f 70 61 79 2f 66 61 63 65 2e 70 68 70 } //01 00  /poker/pay/face.php
		$a_00_4 = {2f 75 73 65 72 70 6c 61 74 66 6f 72 6d 2f 70 61 79 2f 70 61 67 65 2f } //01 00  /userplatform/pay/page/
		$a_00_5 = {70 6c 61 74 66 6f 72 6d 2e 68 61 6e 64 73 6d 61 72 74 2e 6d 6f 62 69 } //01 00  platform.handsmart.mobi
		$a_00_6 = {49 6e 69 74 20 53 4d 53 20 4f 62 73 65 72 76 65 72 } //01 00  Init SMS Observer
		$a_00_7 = {6d 6d 73 63 2e 6d 6f 6e 74 65 72 6e 65 74 2e 63 6f 6d } //00 00  mmsc.monternet.com
		$a_00_8 = {5d 04 00 00 e8 be } //04 80 
	condition:
		any of ($a_*)
 
}
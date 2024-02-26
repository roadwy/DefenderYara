
rule Trojan_AndroidOS_Marcher_B{
	meta:
		description = "Trojan:AndroidOS/Marcher.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 56 75 64 46 4e 55 54 31 41 6d 4a 69 59 3d } //01 00  cmVudFNUT1AmJiY=
		$a_01_1 = {57 65 62 41 70 70 73 20 53 65 72 76 69 63 65 20 73 74 61 72 74 65 64 } //01 00  WebApps Service started
		$a_01_2 = {59 58 57 4c 7a 5a 75 64 75 78 78 6f 4b 78 5a 65 } //01 00  YXWLzZuduxxoKxZe
		$a_01_3 = {59 58 6c 73 59 47 49 6f 48 68 6f 69 71 6b 4a 4b } //00 00  YXlsYGIoHhoiqkJK
	condition:
		any of ($a_*)
 
}
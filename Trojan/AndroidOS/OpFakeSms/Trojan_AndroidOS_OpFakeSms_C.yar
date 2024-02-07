
rule Trojan_AndroidOS_OpFakeSms_C{
	meta:
		description = "Trojan:AndroidOS/OpFakeSms.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 2d 30 30 31 2e 6e 65 74 2f 69 6e 64 65 78 2e 70 68 70 } //01 00  http://m-001.net/index.php
		$a_01_1 = {41 6c 70 68 61 52 65 63 65 69 76 65 72 2e 6a 61 76 61 } //01 00  AlphaReceiver.java
		$a_01_2 = {41 6c 70 68 61 20 73 65 6e 64 52 65 71 75 65 73 74 20 53 54 41 52 54 } //01 00  Alpha sendRequest START
		$a_01_3 = {59 36 43 67 30 33 4e 2e 6a 61 76 61 } //00 00  Y6Cg03N.java
	condition:
		any of ($a_*)
 
}
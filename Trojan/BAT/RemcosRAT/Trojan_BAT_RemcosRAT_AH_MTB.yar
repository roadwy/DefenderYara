
rule Trojan_BAT_RemcosRAT_AH_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 00 74 02 90 01 02 1b 1e 3a 39 90 01 02 00 26 38 20 90 01 02 00 28 17 90 01 02 06 72 99 90 01 02 70 7e 08 90 01 02 04 6f 16 90 01 02 0a 18 3a 0d 90 01 02 00 26 38 cd 90 01 02 ff 11 01 90 00 } //01 00 
		$a_03_1 = {8e 69 1e 3a 18 90 01 02 00 26 26 26 38 0b 90 01 02 00 2a 38 fa 90 01 02 ff 38 f5 90 01 02 ff 38 f0 90 01 02 ff 28 01 90 01 02 0a 38 e7 90 01 02 ff 90 0a 2d 00 02 16 02 90 00 } //01 00 
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_4 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_5 = {49 6e 76 6f 6b 65 45 76 65 6e 74 } //01 00  InvokeEvent
		$a_01_6 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}
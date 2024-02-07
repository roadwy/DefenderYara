
rule Trojan_BAT_Redline_D_MTB{
	meta:
		description = "Trojan:BAT/Redline.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {05 2c 0a 03 46 28 90 01 03 06 0a 2b 03 03 46 0a 04 2d 03 02 2b 1a 02 21 90 01 08 5a 06 6a 61 03 17 58 04 17 59 05 28 90 01 03 06 2a 90 00 } //01 00 
		$a_01_1 = {57 fd a2 35 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 39 00 00 00 27 00 00 00 4a 00 00 00 6b } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_3 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}
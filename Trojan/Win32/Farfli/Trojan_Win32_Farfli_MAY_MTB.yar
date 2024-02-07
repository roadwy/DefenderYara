
rule Trojan_Win32_Farfli_MAY_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 59 72 65 65 6e 51 69 6c 6c 6e 39 37 76 71 7a } //0a 00  cYreenQilln97vqz
		$a_01_1 = {13 28 81 3e bd 25 56 52 f8 27 42 42 c3 35 b7 06 e3 7f f1 15 38 13 4f 6b de 09 23 6b 03 46 ea 39 } //01 00 
		$a_01_2 = {2e 76 6d 70 73 30 } //01 00  .vmps0
		$a_01_3 = {2e 76 6d 70 73 31 } //01 00  .vmps1
		$a_01_4 = {51 75 65 72 79 46 75 6c 6c 50 72 6f 63 65 73 73 49 6d 61 67 65 4e 61 6d 65 57 } //01 00  QueryFullProcessImageNameW
		$a_01_5 = {57 54 53 53 65 6e 64 4d 65 73 73 61 67 65 57 } //00 00  WTSSendMessageW
	condition:
		any of ($a_*)
 
}
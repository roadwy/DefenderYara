
rule Trojan_BAT_RedLineStealer_MH_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 11 0d 16 06 6f 90 01 03 0a 11 0e 6a 59 69 6f 90 01 03 0a 26 11 0a 11 0d 16 06 6f 90 01 03 0a 11 0e 6a 59 69 6f 90 01 03 0a 13 10 7e 90 01 03 04 11 10 16 11 10 8e 69 6f 90 01 03 0a 7e 90 01 03 04 0b 07 16 6a 90 00 } //01 00 
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_4 = {49 00 73 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 50 00 72 00 65 00 73 00 65 00 6e 00 74 00 } //01 00  IsDebuggerPresent
		$a_01_5 = {4f 00 4c 00 4c 00 59 00 44 00 42 00 47 00 } //01 00  OLLYDBG
		$a_01_6 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //01 00  DynamicInvoke
		$a_01_7 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_8 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_9 = {48 69 64 65 50 63 69 74 75 72 65 } //00 00  HidePciture
	condition:
		any of ($a_*)
 
}
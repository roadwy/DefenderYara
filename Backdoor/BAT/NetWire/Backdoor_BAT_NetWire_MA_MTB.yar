
rule Backdoor_BAT_NetWire_MA_MTB{
	meta:
		description = "Backdoor:BAT/NetWire.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 28 90 01 03 06 20 01 00 00 00 7e 90 01 03 04 39 90 01 03 ff 26 20 01 00 00 00 38 90 01 03 ff 02 13 03 20 03 00 00 00 7e 90 01 03 04 3a 90 01 03 ff 26 38 90 01 03 ff 11 00 28 90 01 03 06 11 03 16 11 03 8e 69 28 90 01 03 06 13 06 38 90 01 03 00 11 00 18 6f 90 01 03 0a 38 90 01 03 ff dd 90 01 03 ff 13 02 20 02 00 00 00 fe 90 01 01 04 00 38 90 01 03 ff 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {50 61 74 63 68 50 6f 6c 69 63 79 } //01 00  PatchPolicy
		$a_01_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_5 = {45 00 72 00 72 00 71 00 64 00 67 00 67 00 78 00 64 00 69 00 6d 00 6b 00 } //01 00  Errqdggxdimk
		$a_01_6 = {43 61 6e 63 65 6c 50 6f 6c 69 63 79 } //01 00  CancelPolicy
		$a_01_7 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_8 = {50 75 73 68 49 6e 69 74 69 61 6c 69 7a 65 72 } //01 00  PushInitializer
		$a_01_9 = {73 65 74 5f 4b 65 79 } //00 00  set_Key
	condition:
		any of ($a_*)
 
}
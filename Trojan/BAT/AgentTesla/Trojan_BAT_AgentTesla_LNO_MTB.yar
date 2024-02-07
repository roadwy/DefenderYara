
rule Trojan_BAT_AgentTesla_LNO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 05 6e 11 08 6a 59 d4 11 04 1e 11 08 59 1e 5a 1f 3f 5f 64 20 90 01 03 00 6a 5f d2 9c 11 08 17 59 13 08 90 00 } //01 00 
		$a_01_1 = {24 37 36 33 65 34 33 34 37 2d 34 39 31 64 2d 34 37 66 34 2d 38 30 61 37 2d 34 33 65 31 37 64 63 65 36 63 65 65 } //01 00  $763e4347-491d-47f4-80a7-43e17dce6cee
		$a_01_2 = {53 65 6c 66 20 43 61 6d } //01 00  Self Cam
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_01_6 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}
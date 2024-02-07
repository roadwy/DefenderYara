
rule Trojan_Win64_IcedID_DL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0d 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_1 = {49 68 64 45 72 2e 64 6c 6c } //01 00  IhdEr.dll
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {53 63 72 69 70 74 42 72 65 61 6b } //01 00  ScriptBreak
		$a_01_4 = {43 72 65 61 74 65 49 74 65 6d 4d 6f 6e 69 6b 65 72 } //01 00  CreateItemMoniker
		$a_01_5 = {69 4c 71 56 6b 2e 64 6c 6c } //01 00  iLqVk.dll
		$a_01_6 = {43 67 4e 4d 5a 68 59 41 45 6c 64 } //01 00  CgNMZhYAEld
		$a_01_7 = {4a 4f 47 30 64 78 36 74 77 55 } //01 00  JOG0dx6twU
		$a_01_8 = {4b 54 4d 42 74 67 6c 32 62 45 41 } //01 00  KTMBtgl2bEA
		$a_01_9 = {42 54 4e 6f 30 2e 64 6c 6c } //01 00  BTNo0.dll
		$a_01_10 = {4f 6c 65 44 75 70 6c 69 63 61 74 65 44 61 74 61 } //01 00  OleDuplicateData
		$a_01_11 = {43 72 65 61 74 65 4f 62 6a 72 65 66 4d 6f 6e 69 6b 65 72 } //01 00  CreateObjrefMoniker
		$a_01_12 = {53 63 72 69 70 74 53 74 72 69 6e 67 56 61 6c 69 64 61 74 65 } //00 00  ScriptStringValidate
	condition:
		any of ($a_*)
 
}
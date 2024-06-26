
rule Trojan_BAT_XWorm_CXLM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.CXLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 41 6e 74 69 41 6e 61 6c 79 73 69 73 } //01 00  RunAntiAnalysis
		$a_01_1 = {47 65 74 41 6e 74 69 76 69 72 75 73 } //01 00  GetAntivirus
		$a_01_2 = {43 68 65 63 6b 44 65 66 65 6e 64 65 72 } //01 00  CheckDefender
		$a_01_3 = {43 72 6f 77 64 53 74 72 69 6b 65 } //01 00  CrowdStrike
		$a_01_4 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //01 00  encryptDirectory
		$a_01_5 = {45 6e 63 72 79 70 74 50 61 73 73 77 6f 72 64 } //01 00  EncryptPassword
		$a_01_6 = {53 61 6e 64 42 6f 78 } //01 00  SandBox
		$a_01_7 = {56 69 72 74 75 61 6c 42 6f 78 } //01 00  VirtualBox
		$a_01_8 = {44 44 65 62 75 67 67 65 72 } //01 00  DDebugger
		$a_01_9 = {41 6e 74 69 43 69 73 } //00 00  AntiCis
	condition:
		any of ($a_*)
 
}
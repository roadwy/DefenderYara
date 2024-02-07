
rule Trojan_BAT_Bladabindi_RPF_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 6f 00 69 00 64 00 2e 00 63 00 61 00 74 00 } //01 00  void.cat
		$a_01_1 = {46 75 63 6b 69 6e 50 69 7a 64 65 63 2e 63 6f 72 65 2e 43 6f 6e 66 69 67 } //01 00  FuckinPizdec.core.Config
		$a_01_2 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 35 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //01 00  /C choice /C Y /N /D Y /T 5 & Del
		$a_01_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  cmd.exe
		$a_01_4 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 } //01 00  taskmgr
		$a_01_5 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 68 00 61 00 63 00 6b 00 65 00 72 00 } //01 00  processhacker
		$a_01_6 = {72 00 65 00 67 00 6d 00 6f 00 6e 00 } //01 00  regmon
		$a_01_7 = {66 00 69 00 6c 00 65 00 6d 00 6f 00 6e 00 } //00 00  filemon
	condition:
		any of ($a_*)
 
}

rule Ransom_MSIL_Filecoder_PKC_MSR{
	meta:
		description = "Ransom:MSIL/Filecoder.PKC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,29 00 28 00 06 00 00 0a 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //vssadmin delete shadows /all /quiet & wmic shadowcopy delete  01 00 
		$a_80_1 = {2d 2d 2d 2d 2d 20 41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 20 2d 2d 2d 2d 2d 2d 20 } //----- ALL YOUR FILES ARE ENCRYPTED ------   0a 00 
		$a_80_2 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //bcdedit /set {default} recoveryenabled no  0a 00 
		$a_80_3 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //wbadmin delete catalog -quiet  0a 00 
		$a_80_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  01 00 
		$a_80_5 = {70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //photos, databases and other important are encrypted  00 00 
	condition:
		any of ($a_*)
 
}
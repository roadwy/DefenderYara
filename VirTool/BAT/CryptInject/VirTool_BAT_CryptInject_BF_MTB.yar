
rule VirTool_BAT_CryptInject_BF_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.BF!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 61 75 6c 74 43 6f 64 65 4e 79 6d 4b 46 47 72 79 70 47 } //01 00  FaultCodeNymKFGrypG
		$a_01_1 = {4b 65 79 77 6f 72 64 73 42 4c 41 } //01 00  KeywordsBLA
		$a_01_2 = {52 65 6e 65 77 4f 6e 43 61 6c 6c 54 69 6d 65 } //01 00  RenewOnCallTime
		$a_01_3 = {54 61 72 67 65 74 54 68 42 57 4c 4b } //00 00  TargetThBWLK
	condition:
		any of ($a_*)
 
}
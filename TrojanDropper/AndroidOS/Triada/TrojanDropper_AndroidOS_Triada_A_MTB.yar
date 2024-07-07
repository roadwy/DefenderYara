
rule TrojanDropper_AndroidOS_Triada_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Triada.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 6c 61 63 6b 65 6e 2e 77 6f 72 6b 2e 6d 69 73 63 68 69 65 } //1 com.slacken.work.mischie
		$a_01_1 = {73 74 61 72 74 44 65 74 65 63 74 69 6f 6e 41 6c 61 72 6d } //1 startDetectionAlarm
		$a_01_2 = {54 69 39 32 52 5f 33 37 54 65 74 5f 41 69 54 69 61 } //1 Ti92R_37Tet_AiTia
		$a_01_3 = {52 65 53 65 74 41 64 76 65 72 74 43 61 6c 54 69 6d 65 } //1 ReSetAdvertCalTime
		$a_01_4 = {6d 5f 62 44 65 61 64 53 77 69 74 63 68 } //1 m_bDeadSwitch
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
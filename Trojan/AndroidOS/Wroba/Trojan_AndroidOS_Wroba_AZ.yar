
rule Trojan_AndroidOS_Wroba_AZ{
	meta:
		description = "Trojan:AndroidOS/Wroba.AZ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {6c 61 73 74 20 6f 75 74 67 6f 69 6e 67 20 63 61 6c 6c 6c 6f 67 20 6e 75 6d 62 65 72 3d } //2 last outgoing calllog number=
		$a_01_1 = {43 46 5f 50 68 6f 6e 65 53 74 61 74 65 4c 69 73 74 65 6e 65 72 } //2 CF_PhoneStateListener
		$a_01_2 = {54 42 4c 5f 4e 41 4d 45 5f 4e 55 4d 42 45 52 53 } //2 TBL_NAME_NUMBERS
		$a_01_3 = {6c 6f 63 6b 65 64 57 68 65 6e 43 6f 6d 69 6e 67 } //2 lockedWhenComing
		$a_01_4 = {73 65 43 2f 71 64 74 68 65 79 74 2f 79 64 6a 75 68 64 71 42 2f 6a 75 42 75 66 78 65 64 4f 2f 59 4a 75 42 75 66 78 65 64 4f } //2 seC/qdtheyt/ydjuhdqB/juBufxedO/YJuBufxedO
		$a_01_5 = {70 33 20 73 75 63 63 65 65 64 2c 20 53 65 6e 64 20 46 6f 72 63 65 43 61 6c 6c 44 61 74 61 20 76 69 65 77 3d } //2 p3 succeed, Send ForceCallData view=
		$a_01_6 = {50 43 5f 43 61 6c 6c 52 76 50 72 6f 63 } //2 PC_CallRvProc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=4
 
}
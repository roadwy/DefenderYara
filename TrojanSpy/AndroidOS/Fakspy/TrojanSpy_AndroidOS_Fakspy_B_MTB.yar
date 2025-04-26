
rule TrojanSpy_AndroidOS_Fakspy_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakspy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 6a 69 69 2f 6f 70 74 72 2f 73 65 72 76 69 63 65 2f 75 74 69 6c 73 2f 6f 70 65 72 66 3b } //2 Ljii/optr/service/utils/operf;
		$a_00_1 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //1 getInstalledApplications
		$a_00_2 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getOriginatingAddress
		$a_00_3 = {59 32 39 75 64 47 56 75 64 44 6f 76 4c 33 4e 74 63 77 3d 3d } //1 Y29udGVudDovL3Ntcw==
		$a_00_4 = {4c 30 46 75 5a 48 4a 76 61 57 51 76 4c 6e 4e 35 63 33 52 6c 62 53 38 3d } //1 L0FuZHJvaWQvLnN5c3RlbS8=
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
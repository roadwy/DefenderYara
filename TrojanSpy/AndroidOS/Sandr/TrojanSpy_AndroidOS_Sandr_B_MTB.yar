
rule TrojanSpy_AndroidOS_Sandr_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Sandr.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 6e 65 74 2f 64 72 6f 69 64 6a 61 63 6b 2f 73 65 72 76 65 72 2f 56 69 64 65 6f 43 61 70 44 4a 3b } //2 Lnet/droidjack/server/VideoCapDJ;
		$a_00_1 = {4c 6e 65 74 2f 64 72 6f 69 64 6a 61 63 6b 2f 73 65 72 76 65 72 2f 43 6f 6e 74 72 6f 6c 6c 65 72 3b } //2 Lnet/droidjack/server/Controller;
		$a_01_2 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getOriginatingAddress
		$a_01_3 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //1 getInstalledApplications
		$a_01_4 = {67 65 74 4c 61 75 6e 63 68 49 6e 74 65 6e 74 46 6f 72 50 61 63 6b 61 67 65 } //1 getLaunchIntentForPackage
		$a_01_5 = {61 62 6f 72 74 42 72 6f 61 64 63 61 73 74 } //1 abortBroadcast
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}
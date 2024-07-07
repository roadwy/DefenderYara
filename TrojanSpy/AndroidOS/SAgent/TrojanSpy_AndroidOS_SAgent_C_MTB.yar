
rule TrojanSpy_AndroidOS_SAgent_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgent.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 5f 72 65 63 6f 72 64 } //1 call_record
		$a_01_1 = {3f 61 63 3d 63 68 6b 63 6d 31 26 75 69 64 3d } //1 ?ac=chkcm1&uid=
		$a_01_2 = {59 6f 75 57 69 6c 6c 4e 65 76 65 72 4b 69 6c 6c 4d 65 } //1 YouWillNeverKillMe
		$a_01_3 = {46 52 7a 69 70 31 31 32 2e 7a 69 70 } //1 FRzip112.zip
		$a_01_4 = {61 6e 64 72 6f 69 64 2e 70 65 72 6d 69 73 73 69 6f 6e 2e 52 45 43 4f 52 44 5f 41 55 44 49 4f } //1 android.permission.RECORD_AUDIO
		$a_01_5 = {61 6e 64 72 6f 69 64 2e 70 65 72 6d 69 73 73 69 6f 6e 2e 52 45 41 44 5f 43 41 4c 4c 5f 4c 4f 47 } //1 android.permission.READ_CALL_LOG
		$a_01_6 = {61 63 3d 52 45 50 58 26 75 69 64 3d } //1 ac=REPX&uid=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
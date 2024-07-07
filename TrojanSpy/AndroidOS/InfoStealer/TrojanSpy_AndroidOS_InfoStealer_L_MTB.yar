
rule TrojanSpy_AndroidOS_InfoStealer_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 64 61 74 2f 61 38 61 6e 64 6f 73 65 72 76 65 72 78 2f } //2 Lcom/example/dat/a8andoserverx/
		$a_00_1 = {2f 49 6e 74 65 72 63 65 70 74 43 61 6c 6c 3b } //1 /InterceptCall;
		$a_00_2 = {2f 46 61 6b 65 3b } //1 /Fake;
		$a_00_3 = {2e 61 70 70 2e 61 70 6b } //1 .app.apk
		$a_00_4 = {2f 44 43 49 4d 2f 2e 66 64 61 74 } //1 /DCIM/.fdat
		$a_00_5 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //1 setComponentEnabledSetting
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
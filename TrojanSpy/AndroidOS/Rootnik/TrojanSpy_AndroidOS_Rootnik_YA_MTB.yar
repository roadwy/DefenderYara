
rule TrojanSpy_AndroidOS_Rootnik_YA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Rootnik.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 74 73 65 76 65 6e 74 2e 63 6c 69 63 6b 6d 73 75 6d 6d 65 72 2e 63 6f 6d } //1 statsevent.clickmsummer.com
		$a_00_1 = {67 65 6e 52 6f 6f 74 50 72 6f 63 65 73 73 20 65 78 65 43 6d 64 3d } //1 genRootProcess exeCmd=
		$a_00_2 = {26 6f 73 52 75 6e 74 69 6d 65 3d } //1 &osRuntime=
		$a_00_3 = {73 79 73 74 65 6d 2f 61 70 70 2f 55 53 42 55 73 61 67 65 53 65 72 76 69 63 65 49 6e 66 6f 2e 61 70 6b } //1 system/app/USBUsageServiceInfo.apk
		$a_00_4 = {26 72 65 62 6f 6f 74 43 6f 75 6e 74 3d } //1 &rebootCount=
		$a_02_5 = {68 74 74 70 3a 2f 2f [0-15] 2f 4d 6f 62 69 4c 6f 67 2f 6c 6f 67 2f 61 64 64 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}
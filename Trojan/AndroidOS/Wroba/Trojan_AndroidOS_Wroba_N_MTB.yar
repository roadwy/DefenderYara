
rule Trojan_AndroidOS_Wroba_N_MTB{
	meta:
		description = "Trojan:AndroidOS/Wroba.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 41 70 70 73 } //1 sendApps
		$a_01_1 = {2f 6b 62 73 2e 70 68 70 3f 6d 3d 41 70 69 26 61 3d } //1 /kbs.php?m=Api&a=
		$a_01_2 = {69 73 4f 72 64 65 72 65 64 42 72 6f 61 64 63 61 73 74 } //1 isOrderedBroadcast
		$a_01_3 = {53 45 4d 52 45 43 45 49 56 45 52 5f 44 41 54 41 } //1 SEMRECEIVER_DATA
		$a_01_4 = {4b 52 5f 4e 48 42 61 6e 6b 2e 61 70 6b } //1 KR_NHBank.apk
		$a_01_5 = {63 68 61 6e 67 65 41 70 6b } //1 changeApk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule Trojan_AndroidOS_ScamApp_A_MTB{
	meta:
		description = "Trojan:AndroidOS/ScamApp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 69 72 73 65 6e 69 2f 73 69 6d 70 6c 65 61 6e 64 72 6f 69 64 77 65 62 76 69 65 77 65 78 61 6d 70 6c 65 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b } //4 Lcom/sirseni/simpleandroidwebviewexample/MainActivity;
		$a_00_1 = {73 70 70 72 6f 6d 6f 2e 72 75 2f 61 70 70 73 2e 70 68 70 3f 73 3d } //2 sppromo.ru/apps.php?s=
		$a_00_2 = {7a 7a 77 78 2e 72 75 2f 74 65 73 74 5f 61 72 65 61 31 3f 6b 65 79 77 6f 72 64 3d } //2 zzwx.ru/test_area1?keyword=
		$a_00_3 = {73 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //1 setJavaScriptEnabled
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=7
 
}
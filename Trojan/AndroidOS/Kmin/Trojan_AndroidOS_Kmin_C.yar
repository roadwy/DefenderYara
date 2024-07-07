
rule Trojan_AndroidOS_Kmin_C{
	meta:
		description = "Trojan:AndroidOS/Kmin.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2e 6b 6d 2e 6c 61 75 6e 63 68 65 72 90 02 01 2e 73 65 74 74 69 6e 67 73 90 00 } //1
		$a_01_1 = {73 75 2e 35 6b 33 67 2e 63 6f 6d } //1 su.5k3g.com
		$a_01_2 = {70 6f 72 74 61 6c 2f 6d 2f 63 36 2f 30 2e 61 73 68 78 3f } //1 portal/m/c6/0.ashx?
		$a_01_3 = {73 64 63 61 72 64 2f 4b 4d 49 6e 73 74 61 6c 6c 2f } //1 sdcard/KMInstall/
		$a_00_4 = {6b 6d 2f 63 68 61 72 67 65 2f 48 74 74 70 42 6f 78 } //1 km/charge/HttpBox
		$a_00_5 = {42 62 78 43 68 61 72 67 65 45 6e 67 69 6e 65 } //1 BbxChargeEngine
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}
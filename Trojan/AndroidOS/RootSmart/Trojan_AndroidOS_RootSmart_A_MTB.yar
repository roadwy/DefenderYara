
rule Trojan_AndroidOS_RootSmart_A_MTB{
	meta:
		description = "Trojan:AndroidOS/RootSmart.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {66 61 6b 65 5f 70 61 63 6b 61 67 65 5f 6e 61 6d 65 } //1 fake_package_name
		$a_01_1 = {44 65 6b 76 69 63 65 41 64 6d 69 6e 41 64 64 41 63 74 69 76 69 74 6f 79 } //1 DekviceAdminAddActivitoy
		$a_01_2 = {46 61 6b 6b 65 4c 61 75 6e 63 68 65 72 } //1 FakkeLauncher
		$a_00_3 = {65 78 70 6c 6f 69 74 5f 6f 6e 63 65 } //1 exploit_once
		$a_01_4 = {41 70 6b 70 49 6e 73 74 61 6c 6c 41 63 74 69 76 69 74 6f 79 } //1 ApkpInstallActivitoy
		$a_01_5 = {42 6f 6b 6f 74 52 65 63 65 69 76 65 6f 72 } //1 BokotReceiveor
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
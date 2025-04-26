
rule Trojan_AndroidOS_Defendr_A{
	meta:
		description = "Trojan:AndroidOS/Defendr.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {52 65 73 65 74 69 6e 67 3a 20 ?? ?? ?? ?? 52 65 74 61 69 6e 69 6e 67 3a 20 ?? ?? ?? ?? 53 74 61 72 74 69 6e 67 3a 20 ?? ?? ?? ?? 53 74 6f 70 70 69 6e 67 3a 20 00 } //1
		$a_01_1 = {2f 68 74 6d 6c 2f 62 69 6c 6c 69 6e 67 2f } //1 /html/billing/
		$a_01_2 = {61 6e 64 72 6f 69 64 5f 76 65 72 73 69 6f 6e } //1 android_version
		$a_00_3 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 64 65 66 65 6e 64 65 72 2f } //1 com/android/defender/
		$a_00_4 = {64 65 66 65 6e 64 65 72 2f 61 6e 64 72 6f 69 64 64 65 66 65 6e 64 65 72 2f } //1 defender/androiddefender/
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}
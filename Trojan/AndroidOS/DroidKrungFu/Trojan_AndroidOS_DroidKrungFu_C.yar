
rule Trojan_AndroidOS_DroidKrungFu_C{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6e 6f 73 68 75 66 6f 75 2e 61 6e 64 72 6f 69 64 2e 73 75 } //1 com.noshufou.android.su
		$a_01_1 = {43 50 49 6e 73 74 46 61 69 6c } //1 CPInstFail
		$a_01_2 = {59 50 45 64 73 61 64 61 } //1 YPEdsada
		$a_01_3 = {44 6f 77 6e 46 61 69 6c 65 64 } //1 DownFailed
		$a_01_4 = {6e 65 77 72 70 74 2e 70 68 70 } //1 newrpt.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
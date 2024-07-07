
rule Trojan_AndroidOS_SAgnt_P_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 6e 61 62 6c 65 41 63 74 69 76 69 74 79 41 75 74 6f 54 72 61 63 6b 69 6e 67 } //1 enableActivityAutoTracking
		$a_01_1 = {72 75 2e 6f 6b 2e 61 6e 64 72 6f 69 64 2e 61 63 74 73 2e 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 ru.ok.android.acts.MainActivity
		$a_01_2 = {2f 61 70 6b 73 2f 67 65 74 2d 6c 69 6e 6b 3f 63 6c 69 63 6b 5f 69 64 } //1 /apks/get-link?click_id
		$a_01_3 = {77 69 74 68 50 61 79 6c 6f 61 64 } //1 withPayload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
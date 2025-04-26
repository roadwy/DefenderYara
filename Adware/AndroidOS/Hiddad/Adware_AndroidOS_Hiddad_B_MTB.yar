
rule Adware_AndroidOS_Hiddad_B_MTB{
	meta:
		description = "Adware:AndroidOS/Hiddad.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 63 6c 69 65 6e 74 2e 63 6f 6e 66 69 67 2f 3f 61 70 70 3d 70 6e 64 72 32 26 66 6f 72 6d 61 74 3d 6a 73 6f 6e 26 61 64 76 65 72 74 5f 6b 65 79 3d } //1 /client.config/?app=pndr2&format=json&advert_key=
		$a_01_1 = {26 70 6e 64 72 5f 69 6e 73 74 61 6c 6c 3d 31 } //1 &pndr_install=1
		$a_01_2 = {6c 6f 63 6b 5f 65 6e 61 62 6c 65 5f 61 64 } //1 lock_enable_ad
		$a_01_3 = {49 4e 54 45 4e 54 5f 41 44 5f 53 48 4f 57 } //1 INTENT_AD_SHOW
		$a_01_4 = {6f 6e 41 64 43 6c 69 63 6b 65 64 } //1 onAdClicked
		$a_01_5 = {61 70 69 2e 6a 65 74 65 6e 67 69 6e 65 2e 62 65 } //1 api.jetengine.be
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
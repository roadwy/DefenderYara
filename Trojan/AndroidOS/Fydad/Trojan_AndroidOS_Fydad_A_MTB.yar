
rule Trojan_AndroidOS_Fydad_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Fydad.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6f 6e 41 64 4c 6f 61 64 65 64 } //1 onAdLoaded
		$a_00_1 = {73 65 74 41 64 4c 69 73 74 65 6e 65 72 } //1 setAdListener
		$a_00_2 = {63 6f 6d 2e 76 69 64 30 30 37 2e 76 69 64 65 6f 62 75 64 64 79 } //1 com.vid007.videobuddy
		$a_00_3 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //1 setComponentEnabledSetting
		$a_00_4 = {78 6c 43 68 65 63 6b 41 70 70 49 6e 73 74 61 6c 6c 65 64 } //1 xlCheckAppInstalled
		$a_00_5 = {63 61 6c 6c 44 65 74 61 69 6c 41 63 74 69 76 69 74 79 } //1 callDetailActivity
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
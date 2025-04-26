
rule Trojan_AndroidOS_Hiddad_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddad.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 52 65 73 74 61 72 74 56 69 65 77 41 64 73 53 65 72 76 69 63 65 52 65 63 65 69 76 65 72 3b } //1 /RestartViewAdsServiceReceiver;
		$a_00_1 = {2f 47 65 74 41 64 6d 53 65 72 76 69 63 65 3b } //1 /GetAdmService;
		$a_00_2 = {53 74 6f 70 56 69 65 77 41 64 73 53 65 72 76 69 63 65 } //1 StopViewAdsService
		$a_00_3 = {63 6f 75 6e 74 5f 63 6c 69 63 6b } //1 count_click
		$a_00_4 = {2f 64 65 62 75 67 2f 3f 69 3d } //1 /debug/?i=
		$a_00_5 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //1 setComponentEnabledSetting
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
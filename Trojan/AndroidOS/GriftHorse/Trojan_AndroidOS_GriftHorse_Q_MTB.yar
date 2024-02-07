
rule Trojan_AndroidOS_GriftHorse_Q_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 72 6f 76 69 64 65 43 68 72 6f 6d 65 43 75 73 74 6f 6d 54 61 62 73 43 6f 6d 70 6f 6e 65 6e 74 } //01 00  provideChromeCustomTabsComponent
		$a_00_1 = {70 72 6f 76 69 64 65 53 74 61 72 74 43 6f 6d 70 6f 6e 65 6e 74 } //01 00  provideStartComponent
		$a_00_2 = {69 6e 6a 65 63 74 4d 79 74 72 61 63 6b 65 72 53 65 72 76 69 63 65 } //01 00  injectMytrackerService
		$a_00_3 = {69 6e 6a 65 63 74 4f 6e 65 73 69 67 6e 61 6c 53 65 72 76 69 63 65 } //01 00  injectOnesignalService
		$a_00_4 = {69 6e 6a 65 63 74 41 70 70 73 66 6c 79 65 72 53 65 72 76 69 63 65 } //01 00  injectAppsflyerService
		$a_00_5 = {69 6e 6a 65 63 74 53 69 6d 70 6c 65 57 65 62 56 69 65 77 50 72 65 73 65 6e 74 65 72 } //01 00  injectSimpleWebViewPresenter
		$a_00_6 = {67 65 74 53 75 70 65 72 55 72 6c 53 65 72 76 69 63 65 } //01 00  getSuperUrlService
		$a_00_7 = {67 65 74 53 74 61 72 74 55 72 69 53 65 72 76 69 63 65 } //00 00  getStartUriService
	condition:
		any of ($a_*)
 
}
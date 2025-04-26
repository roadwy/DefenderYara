
rule Trojan_BAT_Reline_MBXT_MTB{
	meta:
		description = "Trojan:BAT/Reline.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 53 41 64 46 46 43 56 4d 65 4a 51 50 62 55 33 74 4d 00 77 68 36 65 37 55 66 57 70 43 6e 59 } //1
		$a_01_1 = {44 36 4b 56 00 4c 6f 61 64 4c } //1 㙄噋䰀慯䱤
		$a_01_2 = {41 64 73 5f 6d 75 6c 74 79 73 61 76 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 Ads_multysave.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
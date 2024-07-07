
rule Trojan_AndroidOS_SanDar_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SanDar.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6b 61 2f 6c 6f 6e 67 65 76 69 74 79 2f 73 65 72 76 69 63 65 2f 52 65 6d 6f 74 65 53 65 72 76 69 63 65 3b } //1 com/ka/longevity/service/RemoteService;
		$a_03_1 = {67 62 77 68 61 74 73 61 70 70 2e 64 6f 77 6e 6c 6f 61 64 2f 90 02 20 61 70 70 2f 61 6e 64 72 6f 69 64 2f 61 70 6b 90 00 } //1
		$a_00_2 = {6c 61 75 6e 63 68 55 6e 6b 6e 6f 77 6e 41 70 70 53 6f 75 72 63 65 73 } //1 launchUnknownAppSources
		$a_00_3 = {63 6f 6c 6c 65 63 74 4e 6f 74 69 66 79 49 6e 66 6f } //1 collectNotifyInfo
		$a_00_4 = {69 6e 73 74 61 6c 6c 41 70 70 } //1 installApp
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
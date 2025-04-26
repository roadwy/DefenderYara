
rule Adware_AndroidOS_CallFlakes_A_MTB{
	meta:
		description = "Adware:AndroidOS/CallFlakes.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 6f 73 74 43 61 6c 6c 4d 61 6e 61 67 65 72 53 44 4b } //1 PostCallManagerSDK
		$a_00_1 = {6c 6f 61 64 41 64 42 61 6e 6e 65 72 53 74 61 72 74 41 70 70 } //1 loadAdBannerStartApp
		$a_00_2 = {77 77 77 2e 66 72 65 65 61 70 70 73 6f 66 74 68 65 64 61 79 2e 63 6f 6d } //1 www.freeappsoftheday.com
		$a_00_3 = {43 61 6c 6c 20 54 65 72 6d 69 6e 61 74 65 20 2d 20 41 64 20 62 61 6e 6e 65 72 } //1 Call Terminate - Ad banner
		$a_00_4 = {43 61 6c 6c 20 54 65 72 6d 69 6e 61 74 65 20 2d 20 52 65 6d 6f 76 65 } //1 Call Terminate - Remove
		$a_00_5 = {63 6c 69 63 6b 4c 69 73 74 65 6e 65 72 41 64 64 43 6f 6e 74 61 63 74 } //1 clickListenerAddContact
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
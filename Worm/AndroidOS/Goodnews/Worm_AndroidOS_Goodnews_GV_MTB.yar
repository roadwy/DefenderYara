
rule Worm_AndroidOS_Goodnews_GV_MTB{
	meta:
		description = "Worm:AndroidOS/Goodnews.GV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 63 74 69 76 65 53 75 62 73 63 72 69 70 74 69 6f 6e 49 6e 66 6f 4c 69 73 74 } //1 getActiveSubscriptionInfoList
		$a_01_1 = {68 61 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //1 has_phone_number
		$a_01_2 = {67 65 74 53 75 62 49 64 } //1 getSubId
		$a_01_3 = {53 74 61 72 74 41 70 70 41 64 } //1 StartAppAd
		$a_01_4 = {54 6f 20 73 74 61 72 74 20 4f 66 66 65 72 73 2c 20 66 6f 6c 6c 6f 77 20 6e 65 78 74 20 73 74 65 70 73 2e 2e 2e } //1 To start Offers, follow next steps...
		$a_01_5 = {43 6f 57 49 4e 20 52 65 67 69 73 74 72 61 74 69 6f 6e 20 50 72 6f 63 65 73 73 } //1 CoWIN Registration Process
		$a_01_6 = {43 6c 69 63 6b 20 6f 6e 20 41 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 20 61 70 70 20 66 72 6f 6d 20 41 64 20 74 6f 20 43 6f 6e 74 69 6e 75 65 } //1 Click on Ad and install app from Ad to Continue
		$a_01_7 = {68 74 74 70 73 3a 2f 2f 74 69 6e 79 2e 63 63 2f 50 75 62 67 2d 49 4e 44 49 41 } //1 https://tiny.cc/Pubg-INDIA
		$a_01_8 = {4e 65 65 64 20 50 65 72 6d 69 73 73 69 6f 6e 20 74 6f 20 73 74 61 72 74 20 61 70 70 21 21 } //1 Need Permission to start app!!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}
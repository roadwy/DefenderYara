
rule Trojan_AndroidOS_Rewardsteal_CY{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.CY,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 61 72 72 65 6e 74 70 72 69 63 69 6e 67 } //2 carrentpricing
		$a_01_1 = {6d 6f 62 69 6c 65 5f 61 70 69 5f 6c 65 76 65 6c } //2 mobile_api_level
		$a_01_2 = {67 65 72 6d 61 6e 2f 53 65 6e 74 52 65 63 65 69 76 65 72 } //2 german/SentReceiver
		$a_01_3 = {44 6f 6d 61 69 6e 55 70 64 61 74 65 52 65 63 65 69 76 65 72 } //2 DomainUpdateReceiver
		$a_01_4 = {73 75 62 73 63 72 69 70 74 69 6f 6e 20 69 6e 66 6f 20 69 73 20 6e 75 6c 6c 20 6f 6e 20 67 65 74 53 69 6d 4e 75 6d 62 65 72 73 } //2 subscription info is null on getSimNumbers
		$a_01_5 = {61 62 6f 75 74 75 73 70 61 67 65 62 6f 6f 6b 70 61 67 65 } //2 aboutuspagebookpage
		$a_01_6 = {63 6f 6e 74 61 63 74 64 65 74 61 69 6c 73 62 6f 6f 6b 70 61 67 65 } //2 contactdetailsbookpage
		$a_01_7 = {64 65 73 63 72 69 70 74 69 6f 6e 70 61 67 65 62 6f 6f 6b 70 61 67 65 } //2 descriptionpagebookpage
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=4
 
}
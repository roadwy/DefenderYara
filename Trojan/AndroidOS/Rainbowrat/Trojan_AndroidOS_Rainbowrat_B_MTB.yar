
rule Trojan_AndroidOS_Rainbowrat_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Rainbowrat.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 52 61 69 6e 62 6f 77 48 61 6e 64 6c 65 72 2f 52 61 69 6e 62 6f 77 43 6f 6d 6d 65 6e 64 48 61 6e 64 6c 65 72 } //1 /RainbowHandler/RainbowCommendHandler
		$a_01_1 = {2f 52 61 69 6e 62 6f 77 48 61 6e 64 6c 65 72 2f 52 61 69 6e 62 6f 77 4b 65 79 6c 6f 67 67 65 72 48 61 6e 64 6c 65 72 } //1 /RainbowHandler/RainbowKeyloggerHandler
		$a_01_2 = {2f 52 61 69 6e 62 6f 77 4e 65 74 77 6f 72 6b 2f 52 61 69 6e 62 6f 77 55 70 6c 6f 61 64 } //1 /RainbowNetwork/RainbowUpload
		$a_01_3 = {52 61 69 6e 62 6f 77 46 69 6c 65 45 78 70 6c 6f 72 65 48 61 6e 64 6c 65 72 } //1 RainbowFileExploreHandler
		$a_01_4 = {67 65 74 4f 6e 4b 65 79 6c 6f 67 67 65 72 } //1 getOnKeylogger
		$a_01_5 = {67 65 74 4f 75 74 67 6f 69 6e 67 53 6d 73 4c 69 73 74 } //1 getOutgoingSmsList
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
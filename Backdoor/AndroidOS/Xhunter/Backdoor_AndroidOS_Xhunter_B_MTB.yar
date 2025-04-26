
rule Backdoor_AndroidOS_Xhunter_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/Xhunter.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 78 68 75 6e 74 65 72 2e 63 6c 69 65 6e 74 } //1 com.xhunter.client
		$a_00_1 = {78 68 75 6e 74 65 72 54 65 73 74 } //1 xhunterTest
		$a_00_2 = {3c 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 3e 3c 3e 3c 3e 3e 3c 3c 3c 3c 3e 53 75 63 63 65 73 73 66 75 6c 6c 79 20 73 74 61 72 74 65 64 20 6d 79 73 65 6c 66 2b 2b 2b 2b 3e 3e 3e 3e 3e 3e 3e 3e } //1 <++++++++++++++++><><>><<<<>Successfully started myself++++>>>>>>>>
		$a_00_3 = {73 65 6e 64 44 61 74 61 54 6f 53 65 72 76 65 72 } //1 sendDataToServer
		$a_00_4 = {67 65 74 69 6e 73 74 61 6c 6c 65 64 61 70 70 73 } //1 getinstalledapps
		$a_00_5 = {64 6f 77 6e 6c 6f 61 64 57 68 61 74 73 61 70 70 44 61 74 61 62 61 73 65 } //1 downloadWhatsappDatabase
		$a_00_6 = {72 65 61 64 43 61 6c 6c 4c 6f 67 } //1 readCallLog
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
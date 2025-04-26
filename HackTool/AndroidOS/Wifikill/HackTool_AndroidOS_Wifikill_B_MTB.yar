
rule HackTool_AndroidOS_Wifikill_B_MTB{
	meta:
		description = "HackTool:AndroidOS/Wifikill.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 69 46 69 4b 69 6c 6c 20 52 55 53 } //1 WiFiKill RUS
		$a_00_1 = {68 61 63 6b } //1 hack
		$a_00_2 = {67 65 74 44 68 63 70 49 6e 66 6f } //1 getDhcpInfo
		$a_00_3 = {70 61 72 61 6e 6f 69 64 2e 6d 65 2f 77 69 66 69 6b 69 6c 6c 2f 64 6f 77 6e 6c 6f 61 64 65 72 } //1 paranoid.me/wifikill/downloader
		$a_00_4 = {67 65 74 49 70 41 64 64 72 65 73 73 } //1 getIpAddress
		$a_00_5 = {4c 6d 65 2f 70 61 72 61 6e 6f 69 64 2f 77 69 66 69 6b 69 6c 6c 2f 73 65 72 76 69 63 65 2f 57 46 4b 53 65 72 76 69 63 65 } //1 Lme/paranoid/wifikill/service/WFKService
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
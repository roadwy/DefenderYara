
rule Trojan_BAT_NewBotLoader_CCHT_MTB{
	meta:
		description = "Trojan:BAT/NewBotLoader.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a a2 25 20 02 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 20 03 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 20 04 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 20 05 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 20 06 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 20 07 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 20 08 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 20 09 00 00 00 20 90 01 01 00 00 00 28 2a 00 00 0a a2 25 90 00 } //1
		$a_01_1 = {3c 47 65 74 49 6e 73 74 61 6c 6c 65 64 45 64 72 3e } //1 <GetInstalledEdr>
		$a_01_2 = {3c 49 6e 6a 65 63 74 3e } //1 <Inject>
		$a_01_3 = {67 65 74 5f 50 61 79 6c 6f 61 64 } //1 get_Payload
		$a_01_4 = {67 65 74 5f 44 6f 6d 61 69 6e 43 6f 6e 74 72 6f 6c 6c 65 72 53 69 74 65 4e 61 6d 65 } //1 get_DomainControllerSiteName
		$a_01_5 = {67 65 74 5f 44 6f 6d 61 69 6e 43 6f 6e 74 72 6f 6c 6c 65 72 46 6f 72 65 73 74 4e 61 6d 65 } //1 get_DomainControllerForestName
		$a_01_6 = {67 65 74 5f 49 6e 73 74 61 6c 6c 65 64 41 6e 74 69 4d 61 6c 77 61 72 65 } //1 get_InstalledAntiMalware
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
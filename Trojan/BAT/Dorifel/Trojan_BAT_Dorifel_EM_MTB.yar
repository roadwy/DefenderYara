
rule Trojan_BAT_Dorifel_EM_MTB{
	meta:
		description = "Trojan:BAT/Dorifel.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 4e 34 38 31 43 35 34 41 38 36 34 46 37 45 43 42 45 } //1 DN481C54A864F7ECBE
		$a_81_1 = {5a 59 44 4e 47 75 61 72 64 } //1 ZYDNGuard
		$a_81_2 = {52 75 6e 48 56 4d } //1 RunHVM
		$a_81_3 = {53 74 61 72 74 75 70 } //1 Startup
		$a_81_4 = {63 68 72 6f 6d 65 4e 6f 74 45 6e 63 6f 64 65 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //1 chromeNotEncode_ProcessedByFody
		$a_81_5 = {42 4f 53 53 46 6c 79 41 77 61 79 } //1 BOSSFlyAway
		$a_81_6 = {43 68 65 63 6b 49 73 49 6e 73 69 64 65 54 65 61 6d 44 75 6e 67 65 6f 6e 44 61 79 } //1 CheckIsInsideTeamDungeonDay
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
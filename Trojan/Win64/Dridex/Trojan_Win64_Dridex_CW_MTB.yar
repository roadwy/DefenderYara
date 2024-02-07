
rule Trojan_Win64_Dridex_CW_MTB{
	meta:
		description = "Trojan:Win64/Dridex.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //03 00  Explorer_Server
		$a_81_1 = {40 69 6e 74 65 72 6e 61 6c 6c 79 47 62 61 72 61 61 67 61 69 6e 73 74 71 } //03 00  @internallyGbaraagainstq
		$a_81_2 = {57 54 77 69 74 74 65 72 2e 61 6c 74 6f 67 65 74 68 65 72 2e 31 31 32 } //03 00  WTwitter.altogether.112
		$a_81_3 = {73 69 74 65 73 41 64 6f 62 65 4d 54 74 72 61 76 69 73 76 69 73 69 74 65 64 47 63 6f 77 62 6f 79 61 69 73 } //03 00  sitesAdobeMTtravisvisitedGcowboyais
		$a_81_4 = {73 63 72 65 65 6e 69 6e 49 6e 74 65 72 6e 65 74 } //03 00  screeninInternet
		$a_81_5 = {6d 69 6e 75 74 65 73 2e 32 39 32 45 63 61 73 75 61 6c 57 65 62 61 63 63 65 73 73 } //03 00  minutes.292EcasualWebaccess
		$a_81_6 = {66 72 6f 6d 43 68 72 6f 6d 65 39 53 65 70 74 65 6d 62 65 72 39 } //00 00  fromChrome9September9
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_TrickbotVP_A_MTB{
	meta:
		description = "Trojan:Win32/TrickbotVP.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {76 70 6e 44 6c 6c 20 62 75 69 6c 64 20 25 73 20 25 73 20 73 74 61 72 74 65 64 } //1 vpnDll build %s %s started
		$a_81_1 = {56 50 4e 20 62 72 69 64 67 65 20 66 61 69 6c 75 72 65 } //1 VPN bridge failure
		$a_81_2 = {31 31 3a 34 33 } //1 11:43
		$a_81_3 = {76 70 6e 44 6c 6c 2e 64 6c 6c } //1 vpnDll.dll
		$a_81_4 = {57 61 6e 74 52 65 6c 65 61 73 65 } //1 WantRelease
		$a_81_5 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 53 74 61 74 75 73 41 } //1 RasGetConnectStatusA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}